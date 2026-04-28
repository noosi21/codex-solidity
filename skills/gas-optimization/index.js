module.exports = {
  name: 'gas-optimization',
  aliases: ['gas', 'compute-optimization'],
  severity: 'low',
  description: 'Gas/Compute Optimization — reveals hidden logic flaws through gas-intensive patterns',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          // Pattern 1: Storage reads in loops
          if (/for\s*\(|while\s*\(/i.test(fnBody) && /\.balance|\.owner|\.totalSupply|mapping/i.test(fnBody)) {
            findings.push({
              title: `Storage Read in Loop — ${fn.name}() wastes gas, may indicate logic flaw`,
              severity: 'low',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              impact: 'Storage reads in loops waste gas AND may indicate a logic flaw — if the loop modifies the same storage variable, the read value changes mid-loop, causing unexpected behavior. This is both a gas issue and a potential security issue.',
              remediation: 'Cache storage reads before the loop: uint256 cachedBalance = balances[user];',
              poc: { scenario: 'Loop reads balances[i] which is also written inside loop → reads stale/modified values' },
            });
          }

          // Pattern 2: Unchecked external call gas waste
          if (fnBody.split(/\.call\s*\(/).length > 3) {
            findings.push({
              title: `Multiple External Calls — ${fn.name}() gas-intensive, potential DOS vector`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              impact: 'Multiple external calls in one function consume significant gas. If any call fails, the entire transaction reverts. This is both a gas optimization opportunity and a DOS vector — an attacker can force calls to fail.',
              remediation: 'Use pull-over-push pattern. Batch external calls. Check return values individually.',
              poc: { scenario: '3+ external calls → high gas → one fails → entire tx reverts → DOS' },
            });
          }

          // Pattern 3: Redundant state variable writes
          const writes = (fnBody.match(/\w+\[/g) || []).length;
          if (writes > 8 && /public|external/i.test(fn.visibility)) {
            findings.push({
              title: `Excessive Storage Writes — ${fn.name}() writes ${writes}+ slots, gas concern`,
              severity: 'low',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              impact: `${writes}+ storage writes per call. Each SSTORE costs 5K-20K gas. This limits usability and may indicate the function does too much in one transaction — a design flaw that could lead to gas griefing or DOS.`,
              remediation: 'Minimize storage writes. Use memory for intermediate calculations. Batch operations.',
              poc: { scenario: `${writes} SSTORE × 20K gas = ${writes * 20}K gas — approaching block limit` },
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
