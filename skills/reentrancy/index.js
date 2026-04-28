module.exports = {
  name: 'reentrancy',
  aliases: ['reentrant', 'reentrancy-attack'],
  severity: 'critical',
  description: 'Reentrancy — drain contract funds via recursive callback before balance update',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;

    for (const file of contracts) {
      if (file.error) continue;
      const source = require('fs').readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const vulnerableFunctions = [];

        for (const fn of contract.functions || []) {
          // Pattern: external call BEFORE state update
          const fnBody = this._extractFunctionBody(source, fn.name, contract.name);
          if (!fnBody) continue;

          const hasExternalCall = /(\w+)\.(transfer|send|call|delegatecall|staticcall)\s*\(/g.test(fnBody);
          const hasStateUpdate = /balances\[|balanceOf|_balances|userBalance|shares|totalSupply|amount/g.test(fnBody);
          const isWithdrawal = /withdraw|claim|redeem|exit|cash|transfer|send|pay|refund/i.test(fn.name);
          const isPayable = fn.mutability === 'payable' || fn.mutability === 'nonpayable';

          if (!hasExternalCall) continue;

          // Check for reentrancy guard
          const hasGuard = /nonReentrant|_notEntered|_status|mutex|_locked|reentrancyGuard/i.test(fnBody) ||
            fn.modifiers?.some(m => /nonReentrant|mutex|locked|noReenter/i.test(m));

          if (hasGuard) continue;

          // Check if state update happens AFTER external call (vulnerable pattern)
          const callIndex = this._findExternalCallIndex(fnBody);
          const stateUpdateIndex = this._findStateUpdateIndex(fnBody);

          const stateAfterCall = callIndex >= 0 && stateUpdateIndex > callIndex;
          const noStateUpdate = callIndex >= 0 && stateUpdateIndex === -1;

          if (stateAfterCall || noStateUpdate || (isWithdrawal && hasExternalCall && !hasGuard)) {
            // Calculate impact
            const hasBalanceTracking = /balances\[|balanceOf|_balances|userBalance/i.test(source);
            const poolSize = this._estimatePoolSize(source);
            const drainCalc = impactEngine.calcReentrancyDrain(poolSize, poolSize > 0 ? Math.floor(poolSize * 0.1) : 1e18);

            vulnerableFunctions.push({
              name: fn.name,
              visibility: fn.visibility,
              mutability: fn.mutability,
              stateAfterCall,
              noStateUpdate,
              isWithdrawal,
            });

            findings.push({
              title: `Reentrancy — ${fn.name}() drains funds via recursive callback`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: {
                vulnerability: stateAfterCall ? 'State update AFTER external call (CEI violation)' : noStateUpdate ? 'No state update before external call' : 'Withdrawal with external call, no reentrancy guard',
                pattern: stateAfterCall ? 'Checks-Effects-Interactions violation' : 'Missing state update',
                line: contract.lineStart,
                code: this._extractVulnerableSnippet(fnBody),
              },
              impact: drainCalc.impact + `. ${stateAfterCall ? 'The contract updates state AFTER the external call, allowing the receiver to re-enter and withdraw again before balance is decremented.' : 'No state update guards the external call, enabling unlimited re-entry.'} This is a COMPLETE FUND DRAIN vulnerability — all user deposits can be stolen by a single attacker.`,
              remediation: 'Follow Checks-Effects-Interactions pattern: update state BEFORE external calls. Add reentrancy guard (OpenZeppelin ReentrancyGuard). Use pull-over-push payment pattern.',
              poc: {
                type: 'exploit_contract',
                code: impactEngine.generateExploitCode('reentrancy'),
                attackFlow: [
                  '1. Deploy ReentrancyAttacker with target contract address',
                  '2. Call attack() with small deposit (e.g., 1 ETH)',
                  '3. Attacker.deposit() sends 1 ETH to target',
                  '4. Attacker.withdraw() triggers target.withdraw()',
                  '5. Target sends ETH → triggers Attacker.receive() callback',
                  '6. Attacker.receive() calls target.withdraw() AGAIN before balance update',
                  '7. Repeat until contract balance = 0',
                  `8. Result: Attacker drains entire pool (${poolSize} wei) with only ${Math.floor(poolSize * 0.1)} wei deposit`,
                ],
                drainCalc,
              },
            });
          }
        }

        // Cross-function reentrancy
        if (vulnerableFunctions.length >= 2) {
          const withdrawFns = vulnerableFunctions.filter(f => /withdraw|claim|redeem/i.test(f.name));
          const depositFns = vulnerableFunctions.filter(f => /deposit|enter|stake/i.test(f.name));
          if (withdrawFns.length > 0 && depositFns.length > 0) {
            findings.push({
              title: `Cross-Function Reentrancy — ${contract.name}`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { withdrawFunctions: withdrawFns.map(f => f.name), depositFunctions: depositFns.map(f => f.name) },
              impact: `Cross-function reentrancy: callback from withdraw() can call deposit() or other state-changing functions, manipulating accounting across functions.`,
              remediation: 'Use a global reentrancy guard that protects ALL state-changing functions, not just individual ones.',
              poc: { scenario: 'Re-enter deposit() during withdraw() callback to inflate balance before withdrawal amount is calculated' },
            });
          }
        }
      }
    }
    return findings;
  },

  _extractFunctionBody(source, fnName, contractName) {
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

  _findExternalCallIndex(body) {
    const patterns = [
      /\.transfer\s*\(/, /\.send\s*\(/, /\.call\s*\(/,
      /\.delegatecall\s*\(/, /\.staticcall\s*\(/,
    ];
    let minIdx = -1;
    for (const p of patterns) {
      const m = body.match(p);
      if (m && (minIdx === -1 || m.index < minIdx)) minIdx = m.index;
    }
    return minIdx;
  },

  _findStateUpdateIndex(body) {
    const patterns = [
      /balances\[/, /balanceOf\[/, /_balances\[/, /userBalance/,
      /totalSupply/, /shares\[/, /\.amount\s*=/,
    ];
    let minIdx = -1;
    for (const p of patterns) {
      const m = body.match(p);
      if (m && (minIdx === -1 || m.index < minIdx)) minIdx = m.index;
    }
    return minIdx;
  },

  _extractVulnerableSnippet(body) {
    if (!body) return '';
    const lines = body.split('\n').filter(l => l.trim());
    return lines.slice(0, 15).join('\n');
  },

  _estimatePoolSize(source) {
    // Look for total supply/deposit indicators
    const totalMatch = source.match(/totalSupply|totalDeposits|poolBalance|totalStaked/i);
    if (totalMatch) return 100e18; // Assume 100 ETH equivalent
    return 50e18; // Default estimate
  },
};
