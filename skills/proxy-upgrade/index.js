module.exports = {
  name: 'proxy-upgrade',
  aliases: ['upgradeable', 'uups', 'transparent-proxy', 'eip-1967'],
  severity: 'critical',
  description: 'Proxy Upgrade — uninitialized implementation, storage gap misalignment, UUPS vs Transparent issues',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const isProxy = /proxy|Proxy|Implementation|implementation|_IMPLEMENTATION_SLOT|_ADMIN_SLOT|Upgradeable|Initializable/i.test(source);
        if (!isProxy) continue;

        // Pattern 1: Uninitialized implementation contract
        if (/initializer|Initializable|_init/i.test(source)) {
          const hasInitCheck = /initialized|_initialized|initializing|_initializing/i.test(source);
          if (!hasInitCheck) {
            findings.push({
              title: `Uninitialized Implementation — anyone can call initializer on implementation directly`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasInitializer: true, noInitGuard: true },
              impact: `The implementation contract has an initializer function but no guard against being called directly. An attacker can:
1. Call initializer() directly on the implementation contract (not the proxy)
2. Set themselves as owner in the implementation's storage
3. Now the implementation contract has an "owner"
4. If anyone delegates through the proxy, the implementation code runs in proxy storage context
5. But if there's any function that reads implementation storage (e.g., version check), attacker's values are used`,
              remediation: 'Add _disableInitializer() in the implementation constructor. Or use OpenZeppelin Initializable which prevents calling initializer on the implementation directly.',
              poc: { attackFlow: ['1. Attacker calls initialize() on implementation contract directly', '2. Sets attacker as owner in implementation storage', '3. If any function reads from implementation storage → attacker controlled', '4. Potential for logic bypass or backdoor'] },
            });
          }
        }

        // Pattern 2: Missing storage gaps
        const hasStorageGap = /uint256\s*\[\d+\]\s*__gap|__gap/i.test(source);
        if (!hasStorageGap && contract.inheritance?.length > 0) {
          findings.push({
            title: `Missing Storage Gaps — adding variables in base contracts breaks upgrade layout`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noStorageGap: true, inheritance: contract.inheritance },
            impact: `Contract inherits from multiple contracts but has no __gap storage variables. When upgrading, if a base contract adds a new state variable, all child contracts' storage slots shift. This causes:
1. Child variables read wrong values from parent slots
2. Owner address overwritten by unrelated variable
3. Balance mapping corrupted
4. Complete fund drain via storage collision

Storage gaps (uint256[50] __gap) reserve slots so base contracts can add variables without shifting child storage.`,
            remediation: 'Add uint256[50] __gap at the end of each upgradeable contract. This reserves 50 slots for future variable additions.',
            poc: {
              attackFlow: [
                '1. V1: Parent has 2 vars (slot 0-1), Child has 1 var (slot 2)',
                '2. V2: Parent adds 1 new var → occupies slot 2',
                '3. Child\'s var shifts from slot 2 to slot 3',
                '4. But proxy storage still has child var at slot 2',
                '5. Child reads slot 3 → gets default value (0)',
                '6. Parent\'s new var at slot 2 reads child\'s old value',
                '7. Storage completely corrupted',
              ],
            },
          });
        }

        // Pattern 3: UUPS — upgrade function in implementation without access control
        if (/upgradeTo|upgradeToAndCall|_authorizeUpgrade|UUPSUpgradeable/i.test(source)) {
          const upgradeFns = contract.functions?.filter(fn => /upgradeTo|upgradeToAndCall/i.test(fn.name)) || [];
          for (const fn of upgradeFns) {
            const hasAuth = fn.modifiers?.some(m => /onlyOwner|onlyAdmin|onlyGovernance|onlyProxyAdmin|_authorizeUpgrade/i.test(m)) ||
              this._extractFunctionBody(source, fn.name)?.includes('_authorizeUpgrade');
            if (!hasAuth) {
              findings.push({
                title: `UUPS Unprotected Upgrade — ${fn.name}() anyone can upgrade implementation`,
                severity: 'critical',
                contract: `${contract.name} (${file.file})`,
                function: fn.name,
                evidence: { noAccessControl: true },
                impact: 'UUPS pattern puts upgrade logic in the implementation. If upgradeTo() has no access control, ANYONE can replace the implementation with a malicious contract. All proxy storage is then controlled by attacker code — complete fund drain.',
                remediation: 'Add onlyOwner or _authorizeUpgrade to upgrade functions. Use OpenZeppelin UUPSUpgradeable which requires _authorizeUpgrade override.',
                poc: { attackFlow: ['1. Attacker calls upgradeTo(maliciousImplementation)', '2. Proxy now delegates to attacker contract', '3. Attacker contract reads/writes proxy storage', '4. Attacker drains all funds from proxy'] },
              });
            }
          }
        }

        // Pattern 4: Transparent proxy — admin functions callable by anyone if no admin check
        if (/ProxyAdmin|_admin|admin/i.test(source) && /fallback|receive/i.test(source)) {
          const hasAdminCheck = /if\s*\(\s*msg\.sender\s*==\s*_admin|require.*admin|onlyProxyAdmin|onlyAdmin/i.test(source);
          if (!hasAdminCheck) {
            findings.push({
              title: `Transparent Proxy — admin functions not properly gated`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { noAdminCheck: true },
              impact: 'Transparent proxy should route admin calls to proxy admin functions and user calls to implementation. If admin check is missing or incorrect, users can call admin functions (like upgrade) through the proxy.',
              remediation: 'Implement proper admin/user routing in fallback. Use OpenZeppelin TransparentUpgradeableProxy.',
              poc: { scenario: 'User calls upgrade function through proxy → not blocked by admin check → implementation replaced' },
            });
          }
        }

        // Pattern 5: Constructor vs Initializer confusion
        if (/constructor\s*\(/i.test(source) && /initializer|_init/i.test(source)) {
          findings.push({
            title: `Constructor + Initializer — confusion about which sets state`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { hasConstructor: true, hasInitializer: true },
            impact: 'Contract has both constructor and initializer. In upgradeable contracts, constructor runs on the IMPLEMENTATION contract (wasted — implementation storage is never used through proxy). Initializer runs on the PROXY storage. If state is set in constructor instead of initializer, it is NOT set in the proxy — all values default to 0. This can mean owner = address(0), breaking all access control.',
            remediation: 'Remove constructor from upgradeable contracts. Move all initialization to initializer function. Use _disableInitializer() in constructor to prevent direct initialization of implementation.',
            poc: { attackFlow: ['1. Constructor sets owner = msg.sender (in implementation storage)', '2. Initializer called on proxy (sets proxy storage)', '3. But initializer doesn\'t set owner → proxy.owner = address(0)', '4. onlyOwner check: msg.sender == address(0) → always false', '5. OR: address(0) check bypassed → anyone can call owner functions'] },
          });
        }

        // Pattern 6: EIP-1967 non-standard slot usage
        if (/_IMPLEMENTATION_SLOT|_ADMIN_SLOT/i.test(source)) {
          const usesStandardSlots = /0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc|0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103/i.test(source);
          if (!usesStandardSlots) {
            findings.push({
              title: `Non-Standard Proxy Storage Slots — collision risk with implementation variables`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { customSlots: true, noEIP1967: true },
              impact: 'Proxy uses custom storage slots instead of EIP-1967 standard slots. Custom slots may collide with implementation contract variables. EIP-1967 uses keccak256 to derive slots that are guaranteed not to collide.',
              remediation: 'Use EIP-1967 standard slots: implementation at bytes32(uint256(keccak256("eip1967.proxy.implementation"))-1), admin at bytes32(uint256(keccak256("eip1967.proxy.admin"))-1).',
              poc: { scenario: 'Custom slot for implementation overlaps with implementation variable → reading implementation address returns wrong value' },
            });
          }
        }
      }
    }
    return findings;
  },

  _extractFunctionBody(source, fnName) {
    const fnRe = new RegExp(`function\\s+${fnName}\\s*\\([^)]*\\)[^{]*\\{`, 'g');
    const match = fnRe.exec(source);
    if (!match) return null;
    const start = source.indexOf('{', match.index) + 1;
    let depth = 1;
    for (let i = start; i < source.length; i++) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') { depth--; if (depth === 0) return source.substring(start, i); }
    }
    return source.substring(start);
  },
};
