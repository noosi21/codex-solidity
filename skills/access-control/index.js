module.exports = {
  name: 'access-control',
  aliases: ['auth', 'privilege-escalation', 'owner-bypass'],
  severity: 'critical',
  description: 'Access Control — unauthorized calls to owner/admin functions, fund drain via privilege escalation',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Functions that should be restricted but lack access control
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name, contract.name);
          if (!fnBody) continue;

          const isSensitive = this._isSensitiveFunction(fn.name, fnBody);
          if (!isSensitive) continue;

          const hasAccessControl = this._hasAccessControl(fn, fnBody, source);
          if (hasAccessControl) continue;

          const impact = this._assessImpact(fn.name, fnBody);
          findings.push({
            title: `Missing Access Control — ${fn.name}() can be called by anyone`,
            severity: impact.severity,
            contract: `${contract.name} (${file.file})`,
            function: fn.name,
            evidence: {
              visibility: fn.visibility,
              mutability: fn.mutability,
              missingModifier: this._expectedModifier(fn.name, fnBody),
              sensitiveActions: this._findSensitiveActions(fnBody),
            },
            impact: impact.description,
            remediation: `Add ${this._expectedModifier(fn.name, fnBody)} modifier to ${fn.name}(). Use OpenZeppelin Ownable or AccessControl.`,
            poc: {
              type: 'direct_call',
              code: impactEngine.generateExploitCode('accessControl'),
              attackFlow: [
                `1. Anyone calls ${fn.name}() directly (no auth check)`,
                `2. ${impact.immediateEffect}`,
                `3. ${impact.downstreamEffect}`,
              ],
            },
          });
        }

        // Pattern 2: tx.origin used for authorization
        const txOriginMatches = [...source.matchAll(/tx\.origin/g)];
        if (txOriginMatches.length > 0) {
          const lineNum = source.substring(0, txOriginMatches[0].index).split('\n').length;
          findings.push({
            title: `tx.origin used for authorization — phishing attack vector`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { line: lineNum, pattern: 'tx.origin', occurrences: txOriginMatches.length },
            impact: 'Contract uses tx.origin for authorization — attacker can phish the owner into calling a malicious contract that triggers the protected function. The call will appear to come from the owner because tx.origin checks the original sender, not the immediate caller.',
            remediation: 'Replace tx.origin with msg.sender for all authorization checks.',
            poc: {
              attackFlow: [
                '1. Attacker creates phishing contract with attractive offer',
                '2. Owner calls phishing contract (tx.origin = owner)',
                '3. Phishing contract calls target.restrictedFunction()',
                '4. tx.origin check passes because original sender IS the owner',
                '5. Attacker executes privileged action through phishing contract',
              ],
            },
          });
        }

        // Pattern 3: Unprotected selfdestruct / suicide
        if (/selfdestruct|suicide\s*\(/i.test(source) && !/onlyOwner|onlyAdmin|onlyGovernance/i.test(source.substring(0, source.indexOf('selfdestruct')))) {
          findings.push({
            title: `Unprotected selfdestruct — contract can be killed by anyone`,
            severity: 'critical',
            contract: `${contract.name} (${file.file})`,
            evidence: { pattern: 'selfdestruct/suicide without access control' },
            impact: 'Anyone can call selfdestruct() and kill the contract. All funds are sent to the caller. All user deposits are permanently lost.',
            remediation: 'Add onlyOwner modifier to selfdestruct. Consider removing selfdestruct entirely.',
            poc: { attackFlow: ['1. Attacker calls selfdestruct(payable(attacker))', '2. Contract is destroyed', '3. All ETH sent to attacker', '4. All user funds permanently lost'] },
          });
        }

        // Pattern 4: Owner can rug pull
        const ownerDrainFns = contract.functions?.filter(fn =>
          /withdraw|transfer|send|sweep|claim|drain|rescue/i.test(fn.name) &&
          fn.modifiers?.some(m => /onlyOwner|onlyAdmin/i.test(m))
        ) || [];

        if (ownerDrainFns.length > 0 && /deposit|invest|stake|enter/i.test(source)) {
          findings.push({
            title: `Centralization Risk — owner can drain all user funds`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              ownerFunctions: ownerDrainFns.map(f => f.name),
              userDepositFunctions: contract.functions?.filter(f => /deposit|invest|stake/i.test(f.name)).map(f => f.name),
            },
            impact: `Owner can call ${ownerDrainFns.map(f => f.name + '()').join(', ')} to withdraw all contract funds. Users who deposited have no guarantee their funds are safe. This is a rug pull vector — even if the owner is honest, a compromised owner key means total fund loss.`,
            remediation: 'Implement timelock on owner withdrawal functions. Use multisig for owner. Add withdrawal limits. Consider governance-controlled withdrawals.',
            poc: { attackFlow: ['1. Users deposit funds into contract', `2. Compromised/malicious owner calls ${ownerDrainFns[0]?.name}()`, '3. All user funds transferred to owner', '4. Users cannot withdraw — funds gone'] },
          });
        }

        // Pattern 5: Uninitialized proxy / implementation
        if (/proxy|implementation|_IMPLEMENTATION_SLOT|_ADMIN_SLOT/i.test(source)) {
          if (!/initializer|_init/i.test(source) || /constructor\s*\(/i.test(source)) {
            findings.push({
              title: `Potentially uninitialized proxy — implementation takeover`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { pattern: 'Proxy pattern detected, possible initialization issue' },
              impact: 'If proxy implementation slot is uninitialized, attacker can set it to their own contract address. All delegatecalls will execute attacker code with proxy storage — full fund drain and contract takeover.',
              remediation: 'Initialize implementation in constructor or initializer. Use OpenZeppelin proxy patterns. Verify implementation is set before any delegatecall.',
              poc: { attackFlow: ['1. Attacker calls proxy with function that triggers delegatecall', '2. Implementation slot is zero/uninitialized', '3. Attacker sets implementation to malicious contract', '4. All subsequent calls execute attacker code'] },
            });
          }
        }
      }
    }
    return findings;
  },

  _isSensitiveFunction(name, body) {
    const sensitiveNames = /withdraw|transfer|send|mint|burn|pause|unpause|setFee|setRate|setPrice|updatePrice|configure|setOwner|renounceOwnership|sweep|drain|rescue|claim|upgrade|setImplementation|setTarget|addAdmin|removeAdmin|setLimit|setCap|setReward/i;
    const sensitiveActions = /msg\.value|payable|transfer|send|selfdestruct|delegatecall|assembly/i.test(body);
    return sensitiveNames.test(name) || (sensitiveActions && /owner|admin|fee|rate|price/i.test(body));
  },

  _hasAccessControl(fn, body, source) {
    if (fn.modifiers?.some(m => /onlyOwner|onlyAdmin|onlyGovernance|onlyRole|onlyMinter|onlyPauser|nonReentrant|whenNotPaused|auth/i.test(m))) return true;
    if (/require\s*\(\s*msg\.sender\s*==\s*owner|require\s*\(\s*msg\.sender\s*==\s*_owner|require\s*\(\s*_msgSender|require\s*\(\s*hasRole|require\s*\(\s*access/i.test(body)) return true;
    if (fn.visibility === 'internal' || fn.visibility === 'private') return true;
    return false;
  },

  _expectedModifier(name, body) {
    if (/owner|admin|governance|upgrade|setImplementation/i.test(name + body)) return 'onlyOwner';
    if (/mint|burn/i.test(name)) return 'onlyMinter (or onlyRole(MINTER_ROLE))';
    if (/pause|unpause/i.test(name)) return 'onlyPauser (or onlyRole(PAUSER_ROLE))';
    return 'onlyOwner or onlyAdmin';
  },

  _findSensitiveActions(body) {
    const actions = [];
    if (/transfer|send/i.test(body)) actions.push('ETH/token transfer');
    if (/selfdestruct/i.test(body)) actions.push('Contract destruction');
    if (/delegatecall/i.test(body)) actions.push('Delegatecall execution');
    if (/assembly/i.test(body)) actions.push('Inline assembly');
    if (/mint/i.test(body)) actions.push('Token minting');
    if (/burn/i.test(body)) actions.push('Token burning');
    if (/setFee|setRate|setPrice/i.test(body)) actions.push('Fee/rate/price modification');
    return actions;
  },

  _assessImpact(name, body) {
    if (/withdraw.*all|sweep|drain|rescue/i.test(name)) return {
      severity: 'critical',
      description: 'Anyone can call this function to drain ALL contract funds. Complete fund theft — all user deposits stolen.',
      immediateEffect: 'All contract balance is transferred to the caller',
      downstreamEffect: 'All users lose their deposits permanently',
    };
    if (/transfer|send|withdraw/i.test(name)) return {
      severity: 'critical',
      description: 'Unauthorized fund transfer — attacker can steal contract funds or redirect payments.',
      immediateEffect: 'Funds transferred to attacker-controlled address',
      downstreamEffect: 'Contract becomes insolvent, users cannot withdraw',
    };
    if (/mint/i.test(name)) return {
      severity: 'critical',
      description: 'Unauthorized minting — attacker can mint unlimited tokens, diluting all holders to zero value.',
      immediateEffect: 'Attacker mints tokens to their address',
      downstreamEffect: 'Token value drops to zero due to infinite supply',
    };
    if (/setFee|setRate|setPrice/i.test(name)) return {
      severity: 'high',
      description: 'Anyone can modify fees/rates — attacker can set 100% fee to drain all user transactions.',
      immediateEffect: 'Fee/rate set to extreme value',
      downstreamEffect: 'Users pay 100% fees or get incorrect prices',
    };
    if (/pause/i.test(name)) return {
      severity: 'high',
      description: 'Anyone can pause the contract — all user funds locked (DOS/griefing).',
      immediateEffect: 'Contract paused, all operations frozen',
      downstreamEffect: 'Users cannot withdraw, trade, or interact',
    };
    return {
      severity: 'high',
      description: 'Unauthorized access to sensitive function — potential for fund theft, data manipulation, or contract takeover.',
      immediateEffect: 'Sensitive action executed without authorization',
      downstreamEffect: 'Contract integrity compromised',
    };
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
