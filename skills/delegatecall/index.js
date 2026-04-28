module.exports = {
  name: 'delegatecall',
  aliases: ['storage-collision', 'proxy-takeover'],
  severity: 'critical',
  description: 'Delegatecall Injection — storage collision, contract takeover via malicious implementation',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Delegatecall with user-controlled target
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          if (!/delegatecall/i.test(fnBody)) continue;

          // Check if target address is controllable
          const targetIsParam = fn.params?.split(',').some(p => /target|implementation|_impl|addr|to|callee/i.test(p));
          const targetIsStorage = /implementation|_IMPLEMENTATION_SLOT|_target|_impl/i.test(fnBody);
          const hasAccessControl = fn.modifiers?.some(m => /onlyOwner|onlyAdmin|onlyGovernance/i.test(m));

          if ((targetIsParam || !targetIsStorage) && !hasAccessControl) {
            findings.push({
              title: `Delegatecall to User-Controlled Address — ${fn.name}() allows arbitrary code execution`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { targetIsParam, targetIsStorage, noAccessControl: !hasAccessControl },
              impact: 'Attacker can pass their own contract address as delegatecall target. The attacker\'s code executes in the context of the calling contract\'s storage. This gives FULL CONTROL: overwrite owner, drain funds, modify any state variable. Complete contract takeover.',
              remediation: 'Never allow user-controlled delegatecall targets. Restrict to onlyOwner. Use fixed implementation addresses or EIP-1967 proxy pattern.',
              poc: {
                attackFlow: [
                  '1. Attacker deploys malicious contract with function matching expected signature',
                  '2. Attacker calls target function with their contract address',
                  '3. Malicious code runs via delegatecall — in proxy storage context',
                  '4. Attacker overwrites owner to their address',
                  '5. Attacker calls withdrawAll() as new owner',
                  '6. All funds drained — contract fully compromised',
                ],
                code: impactEngine.generateExploitCode('accessControl'),
              },
            });
          }

          // Pattern 2: Storage layout mismatch between proxy and implementation
          if (targetIsStorage && contract.inheritance?.length > 0) {
            findings.push({
              title: `Storage Collision Risk — proxy and implementation layout mismatch`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { proxyPattern: true, stateVars: contract.stateVariables?.map(v => `${v.type} ${v.name}`) },
              impact: 'If proxy and implementation have different storage layouts, delegatecall will read/write wrong slots. Example: implementation\'s "owner" at slot 0 maps to proxy\'s "balance" at slot 0 → writing owner overwrites balances. This can enable fund theft or access control bypass.',
              remediation: 'Use EIP-1967 storage slots for proxy-specific variables. Use OpenZeppelin upgradeable contracts. Verify storage layout with upgrade checks.',
              poc: { scenario: 'Implementation stores address public owner at slot 0, proxy stores mapping balances at slot 0 → delegatecall writes owner address into balances mapping' },
            });
          }
        }

        // Pattern 3: Unprotected proxy upgrade
        if (/upgradeTo|_upgradeTo|setImplementation|_setImplementation/i.test(source)) {
          const upgradeFns = contract.functions?.filter(fn => /upgrade|setImplementation/i.test(fn.name)) || [];
          for (const fn of upgradeFns) {
            const hasAuth = fn.modifiers?.some(m => /onlyOwner|onlyAdmin|onlyGovernance|onlyProxyAdmin/i.test(m));
            if (!hasAuth) {
              findings.push({
                title: `Unprotected Proxy Upgrade — ${fn.name}() anyone can change implementation`,
                severity: 'critical',
                contract: `${contract.name} (${file.file})`,
                function: fn.name,
                evidence: { noAccessControl: true },
                impact: 'Anyone can call upgradeTo() to replace the implementation contract. Attacker deploys malicious implementation, upgrades proxy to point to it. All user funds stolen, all storage overwritten.',
                remediation: 'Add onlyOwner or onlyProxyAdmin to upgrade functions. Use Timelock for upgrades. Multi-sig for proxy admin.',
                poc: { attackFlow: ['1. Attacker deploys malicious implementation with backdoor', `2. Attacker calls ${fn.name}(maliciousAddress)`, '3. All future calls execute attacker code', '4. Attacker drains all funds via backdoor'] },
              });
            }
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
