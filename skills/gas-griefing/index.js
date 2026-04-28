module.exports = {
  name: 'gas-griefing',
  aliases: ['gas-dos', 'gas-limit', 'block-gas-limit'],
  severity: 'medium',
  description: 'Gas Griefing — force high gas consumption to DOS other users, block withdrawals via gas limit',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Unbounded loops in critical functions
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const hasLoop = /for\s*\(|while\s*\(/i.test(fnBody);
          if (!hasLoop) continue;

          const isCritical = /withdraw|claim|redeem|exit|transfer|send|sweep|rescue|emergency/i.test(fn.name);
          if (!isCritical) continue;

          const loopOverArray = /for\s*\(\s*(?:uint|uint256|int)\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length/i.test(fnBody);
          if (loopOverArray) {
            findings.push({
              title: `Gas Griefing — ${fn.name}() loops over growable array, can exceed block gas limit`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { criticalFunction: true, hasLoop: true, loopOverArray: true },
              impact: `Critical function ${fn.name}() iterates over an array that can be grown by external users. Attacker inflates the array until the loop exceeds the block gas limit (~30M gas). Once this happens, ${fn.name}() becomes permanently uncallable — ALL users who depend on this function are locked out. If this is a withdrawal function, all user funds are permanently frozen.`,
              remediation: 'Replace iteration with pull-over-push pattern. Use pagination. Never loop over user-growable arrays in critical functions.',
              poc: {
                attackFlow: [
                  `1. Attacker creates many small entries in the iterated array`,
                  '2. Each entry adds ~5K-50K gas per iteration',
                  '3. After ~600-6000 entries, loop exceeds block gas limit',
                  `4. ${fn.name}() always runs out of gas — permanently fails`,
                  '5. ALL users affected — funds locked',
                  '6. Attacker cost: minimal (just gas for small entries)',
                ],
              },
            });
          }
        }

        // Pattern 2: High gas fallback/receive — DOS via gas-intensive callback
        if (contract.hasFallback || contract.hasReceive) {
          const fallbackBody = this._extractFallbackBody(source);
          if (fallbackBody && fallbackBody.length > 100) {
            findings.push({
              title: `Complex Fallback/Receive — high gas consumption blocks ETH transfers`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasComplexFallback: true, fallbackLength: fallbackBody.length },
              impact: 'Contract has a complex fallback/receive function. Any ETH transfer to this contract triggers the fallback. If the fallback is gas-intensive, transfers using .transfer() (2300 gas) or .send() (2300 gas) will always fail. This DOSes any contract that tries to send ETH to this contract using .transfer()/.send().',
              remediation: 'Keep fallback/receive minimal. Use .call{value: x}("") for ETH transfers. Consider pull-over-push pattern.',
              poc: { attackFlow: ['1. Contract has complex fallback() using >2300 gas', '2. Another contract sends ETH via .transfer()', '3. .transfer() forwards only 2300 gas', '4. Fallback runs out of gas → transfer fails', '5. All push-payments to this contract fail'] },
            });
          }
        }

        // Pattern 3: External call in loop — gas accumulation DOS
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const hasLoop = /for\s*\(|while\s*\(/i.test(fnBody);
          const hasExternalCallInLoop = hasLoop && /\.call|\.transfer|\.send|\.delegatecall/i.test(fnBody);

          if (hasExternalCallInLoop) {
            findings.push({
              title: `External Call in Loop — ${fn.name}() gas cost scales with array length`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { externalCallInLoop: true },
              impact: `${fn.name}() makes external calls inside a loop. Each external call costs at least ~25K gas (for ETH transfer). With N iterations, total gas = N * 25K + overhead. After ~1200 iterations, the function exceeds the block gas limit and becomes permanently uncallable. Attacker only needs to grow the array to ~1200 entries to DOS this function.`,
              remediation: 'Use pull-over-push: let each user claim individually instead of pushing in a loop. If iteration is necessary, add pagination (process N items per call).',
              poc: {
                attackFlow: [
                  '1. Function iterates array and calls .transfer() for each entry',
                  '2. Each .transfer() costs ~25K gas',
                  '3. 1200 entries × 25K gas = 30M gas (block limit)',
                  '4. Function permanently fails at 1200+ entries',
                  '5. Attacker creates 1200 entries (cost: ~0.5 ETH gas)',
                  '6. ALL users locked out — funds frozen',
                ],
                estimatedDOSThreshold: '~1200 entries (at 25K gas per external call)',
              },
            });
          }
        }

        // Pattern 4: Mapping iteration attempt — impossible but reveals design flaw
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          // Check for assembly-level mload/gas manipulation
          if (/assembly/i.test(fnBody) && /gas/i.test(fnBody)) {
            findings.push({
              title: `Assembly Gas Manipulation — ${fn.name}() uses gas in assembly`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { assemblyGas: true },
              impact: 'Function uses gas-related operations in inline assembly. This can be used to: (1) force specific gas amounts for external calls, (2) check remaining gas to create conditional logic that behaves differently under gas constraints, (3) create gas-griefing vectors by consuming large amounts of gas intentionally.',
              remediation: 'Avoid gas-dependent logic in assembly. Ensure gas consumption is predictable and bounded.',
              poc: { scenario: 'Assembly checks gas() to decide execution path → different behavior under different gas amounts → unexpected state changes' },
            });
          }
        }

        // Pattern 5: Large storage writes in hot path
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const storageWrites = (fnBody.match(/\w+\[/g) || []).length;
          const isHotPath = /transfer|swap|withdraw|deposit|stake/i.test(fn.name);

          if (isHotPath && storageWrites > 10) {
            findings.push({
              title: `Excessive Storage Writes in Hot Path — ${fn.name}() writes ${storageWrites} storage slots`,
              severity: 'low',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { storageWrites, isHotPath: true },
              impact: `Hot path function ${fn.name}() writes to ${storageWrites}+ storage slots. Each SSTORE costs 5K-20K gas. This makes the function very expensive, potentially exceeding gas limits for complex operations. While not directly exploitable, it limits the function's usability and creates DOS risk under heavy load.`,
              remediation: 'Minimize storage writes in hot paths. Use memory for intermediate calculations. Batch storage writes. Use EIP-1967 storage patterns for proxy variables.',
              poc: { scenario: `${storageWrites} SSTORE operations × 20K gas = ${storageWrites * 20}K gas minimum — close to block limit for complex transactions` },
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

  _extractFallbackBody(source) {
    const fallbackRe = /fallback\s*\(\s*\)\s*(?:external\s+)?(?:payable\s+)?\{/g;
    const match = fallbackRe.exec(source);
    if (!match) {
      const receiveRe = /receive\s*\(\s*\)\s*(?:external\s+)?payable\s*\{/g;
      const rMatch = receiveRe.exec(source);
      if (!rMatch) return null;
      const start = source.indexOf('{', rMatch.index) + 1;
      let depth = 1;
      for (let i = start; i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}') { depth--; if (depth === 0) return source.substring(start, i); }
      }
      return source.substring(start);
    }
    const start = source.indexOf('{', match.index) + 1;
    let depth = 1;
    for (let i = start; i < source.length; i++) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') { depth--; if (depth === 0) return source.substring(start, i); }
    }
    return source.substring(start);
  },
};
