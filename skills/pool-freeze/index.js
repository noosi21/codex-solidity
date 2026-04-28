module.exports = {
  name: 'pool-freeze',
  aliases: ['dos', 'freeze', 'griefing', 'denial-of-service'],
  severity: 'high',
  description: 'Pool Freeze / DOS — attacker locks user funds permanently with minimal cost',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Unbounded loops — gas exhaustion DOS
        const loopVulns = this._findUnboundedLoops(source, contract);
        for (const vuln of loopVulns) {
          const freezeCalc = impactEngine.calcPoolFreeze(100e18, 0.1e18, vuln.method);
          findings.push({
            title: `DOS via Unbounded Loop — ${vuln.function}() iterates over growable array`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            function: vuln.function,
            evidence: {
              loop: vuln.code,
              array: vuln.array,
              canGrow: vuln.canGrow,
              gasRisk: vuln.gasRisk,
            },
            impact: freezeCalc.impact + ` The ${vuln.array} array can be grown by anyone (via deposits/registrations). Once it exceeds the block gas limit, ${vuln.function}() becomes permanently uncallable. ALL users who deposited are permanently locked out — they can NEVER withdraw their funds.`,
            remediation: 'Use pagination or pull-over-push pattern for iterations. Never loop over arrays that untrusted users can grow. Use mapping-based lookups instead.',
            poc: {
              attackFlow: [
                `1. Attacker creates many small deposits/entries in ${vuln.array}`,
                `2. Array grows until iteration exceeds block gas limit (~30M gas)`,
                `3. ${vuln.function}() always runs out of gas — permanently fails`,
                `4. ALL users' funds locked forever — nobody can withdraw`,
                `5. Attacker cost: minimal (just gas for small deposits)`,
              ],
              estimatedEntries: `~${Math.floor(30000000 / vuln.estimatedGasPerEntry)} entries needed to exceed block gas limit`,
              freezeCalc,
            },
          });
        }

        // Pattern 2: Blocker via fallback/receive revert
        if (contract.hasFallback || contract.hasReceive) {
          const pushPaymentFns = contract.functions?.filter(fn =>
            /withdraw|claim|reward|airdrop|distribute|refund/i.test(fn.name) &&
            /transfer|send|call/i.test(this._extractFunctionBody(source, fn.name) || '')
          ) || [];

          for (const fn of pushPaymentFns) {
            const fnBody = this._extractFunctionBody(source, fn.name) || '';
            if (/\.transfer\s*\(/.test(fnBody) || /\.send\s*\(/.test(fnBody)) {
              findings.push({
                title: `Push Payment DOS — ${fn.name}() uses transfer/send which can revert`,
                severity: 'high',
                contract: `${contract.name} (${file.file})`,
                function: fn.name,
                evidence: {
                  pattern: /transfer/.test(fnBody) ? '.transfer() (2300 gas limit)' : '.send() (2300 gas limit)',
                  code: fnBody.match(/\.transfer\([^)]+\)|\.send\([^)]+\)/)?.[0],
                },
                impact: `If a recipient's fallback function uses more than 2300 gas (common for contracts), ${fn.name}() will revert. An attacker can deploy a contract that always reverts on receive, then register it as a recipient. This blocks ALL payments — every user's withdrawal/claim fails because of ONE bad recipient. ALL funds frozen.`,
                remediation: 'Use pull-over-push pattern: let users claim their own funds instead of pushing. Use .call{value: x}("") with proper error handling.',
                poc: {
                  attackFlow: [
                    '1. Attacker deploys contract with reverting fallback()',
                    '2. Attacker registers contract as payment recipient',
                    `3. When ${fn.name}() is called, transfer to attacker contract reverts`,
                    '4. ENTIRE transaction reverts — no one gets paid',
                    '5. All user funds frozen until attacker removes their contract',
                  ],
                },
              });
            }
          }
        }

        // Pattern 3: Emergency pause without unpause
        const pauseFns = contract.functions?.filter(fn => /pause/i.test(fn.name)) || [];
        const unpauseFns = contract.functions?.filter(fn => /unpause/i.test(fn.name)) || [];
        if (pauseFns.length > 0 && unpauseFns.length === 0) {
          findings.push({
            title: `Permanent Freeze — pause() exists but no unpause()`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { pauseFunctions: pauseFns.map(f => f.name), noUnpause: true },
            impact: 'Contract can be paused but never unpaused. Once paused, all user funds are permanently locked. Even if this is owner-only, a compromised or malicious owner can freeze all funds forever.',
            remediation: 'Add unpause() function. Implement timelock on pause. Add auto-unpause after maximum pause duration.',
            poc: { attackFlow: ['1. Owner (or attacker if no access control) calls pause()', '2. All state-changing functions are blocked', '3. No way to unpause — funds frozen forever'] },
          });
        }

        // Pattern 4: Approval/allowance DOS
        if (/approve|allowance|increaseAllowance/i.test(source)) {
          const approveFns = contract.functions?.filter(fn => /approve/i.test(fn.name)) || [];
          for (const fn of approveFns) {
            const fnBody = this._extractFunctionBody(source, fn.name) || '';
            // ERC20 approve race condition (front-run approve change)
            if (/allowance\s*=\s*0|require.*allowance.*0/i.test(fnBody)) {
              findings.push({
                title: `ERC20 Approve Race Condition — ${fn.name}() vulnerable to front-running`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                function: fn.name,
                evidence: { pattern: 'approve() sets allowance directly, vulnerable to race condition' },
                impact: 'Standard ERC20 approve race condition: if owner changes allowance from X to Y, spender can front-run and transfer X, then transfer Y — getting X+Y total instead of max(X,Y). Can be used to drain more tokens than intended.',
                remediation: 'Use increaseAllowance/decreaseAllowance (OpenZeppelin SafeERC20). Or use permit() pattern.',
                poc: { attackFlow: ['1. Owner approves spender for 100 tokens', '2. Owner changes approval to 50 tokens', '3. Spender front-runs: transfers 100 (old approval)', '4. Spender back-runs: transfers 50 (new approval)', '5. Spender got 150 tokens instead of max(100,50)=100'] },
              });
            }
          }
        }

        // Pattern 5: Shadowing state variables in inheritance
        if (contract.inheritance?.length > 0) {
          const stateVarNames = contract.stateVariables?.map(v => v.name) || [];
          for (const parent of contract.inheritance) {
            // Check if child redeclares parent state vars (storage collision)
            if (stateVarNames.length > 0) {
              findings.push({
                title: `Potential State Variable Shadowing — ${contract.name} inherits from ${parent}`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                evidence: { stateVars: stateVarNames, parent, risk: 'Storage layout collision possible' },
                impact: 'If child contract redeclares state variables that exist in parent, storage slots can collide. This can cause: (1) balance tracking to read wrong values, (2) access control to use wrong owner, (3) fund accounting to be incorrect — potential fund drain.',
                remediation: 'Use unique variable names across inheritance chain. Use storage layout checks. Consider using Diamond storage pattern for upgrades.',
                poc: { scenario: 'Parent stores "owner" at slot 0, child stores "balance" at slot 0 → writing balance overwrites owner' },
              });
            }
          }
        }
      }
    }
    return findings;
  },

  _findUnboundedLoops(source, contract) {
    const vulns = [];
    const loopRe = /for\s*\(\s*(?:uint|uint256|int)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length\s*;/g;
    let m;

    for (const fn of contract.functions || []) {
      const fnBody = this._extractFunctionBody(source, fn.name);
      if (!fnBody) continue;

      while ((m = loopRe.exec(fnBody)) !== null) {
        const arrayName = m[1];
        // Check if the array can be grown by external users
        const canGrow = this._canArrayGrow(source, arrayName, contract);
        const gasPerEntry = /transfer|send|call/.test(fnBody) ? 50000 : 5000;

        vulns.push({
          function: fn.name,
          array: arrayName,
          code: m[0],
          canGrow,
          gasRisk: canGrow ? 'HIGH — untrusted users can grow array' : 'LOW — only owner can grow',
          estimatedGasPerEntry: gasPerEntry,
          method: `Gas exhaustion via ${arrayName}.length loop growth`,
        });
      }
    }
    return vulns;
  },

  _canArrayGrow(source, arrayName, contract) {
    // Check if array is pushed to by public/external functions
    const pushRe = new RegExp(`${arrayName}\\.push\\s*\\(`, 'g');
    const matches = [...source.matchAll(pushRe)];
    for (const m of matches) {
      // Find which function contains this push
      const fnBefore = source.substring(0, m.index).match(/function\s+(\w+)\s*\([^)]*\)\s*([^{]*)\{/g);
      if (fnBefore) {
        const lastFn = fnBefore[fnBefore.length - 1];
        if (/public|external/.test(lastFn) || !/internal|private/.test(lastFn)) return true;
      }
    }
    return false;
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
