module.exports = {
  name: 'rounding-errors',
  aliases: ['rounding', 'precision-loss', 'truncation'],
  severity: 'high',
  description: 'Rounding Errors — share/token calculations round down, attacker extracts dust per tx, scales across pool',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Division before multiplication — precision loss
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          // Find division before multiplication patterns
          const divBeforeMul = this._findDivBeforeMul(fnBody);
          for (const vuln of divBeforeMul) {
            findings.push({
              title: `Division Before Multiplication — ${fn.name}() loses precision`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { code: vuln.code, pattern: vuln.pattern },
              impact: `In ${fn.name}(), division happens before multiplication: ${vuln.code}. Solidity integer division truncates (rounds down). When you divide first, the precision loss is amplified by the subsequent multiplication. Example: (100 / 3) * 3 = 99, not 100. Over many transactions, this precision loss accumulates. An attacker can exploit this by: (1) making many small transactions that each lose 1 wei, (2) the "lost" wei accumulate in the contract, (3) attacker or owner can sweep the accumulated dust.`,
              remediation: 'Always multiply BEFORE dividing: (amount * rate) / BASE instead of (amount / BASE) * rate. Use higher precision intermediates (e.g., 1e18 instead of 1e6).',
              poc: {
                attackFlow: [
                  `1. ${fn.name}() calculates: (userBalance / totalSupply) * rewardPool`,
                  '2. userBalance = 1, totalSupply = 3, rewardPool = 30',
                  '3. (1 / 3) * 30 = 0 * 30 = 0 — user gets NOTHING',
                  '4. Correct: (1 * 30) / 3 = 30 / 3 = 10 — user should get 10',
                  '5. Attacker exploits by ensuring they always round down',
                  '6. Accumulated "lost" value stays in contract for attacker to extract',
                ],
              },
            });
          }
        }

        // Pattern 2: Share conversion rounding — deposit gets fewer shares
        const hasShareConversion = /convertToShares|shares.*=.*amount.*totalSupply|_mint.*shares/i.test(source);
        if (hasShareConversion) {
          const hasCeilDeposit = /ceil|Math\.ceil|divCeil|divUp|roundUp|mulDivUp/i.test(source);
          if (!hasCeilDeposit) {
            findings.push({
              title: `Share Conversion Rounds Down on Deposit — attacker gets fewer shares than entitled`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasShareConversion: true, noCeilDivision: true },
              impact: 'When converting assets to shares, the calculation rounds down. This means depositors get slightly fewer shares than they should. The "missing" fractional shares accumulate as value in the vault, benefiting existing shareholders (or the attacker who deposits first). Over time with many deposits, significant value accumulates from rounding.',
              remediation: 'For deposits, use ceil division (round UP shares) so depositor gets slightly MORE shares — the vault keeps the dust. For withdrawals, use floor division (round DOWN assets) so vault keeps dust. This follows the "round in favor of the vault" principle.',
              poc: { attackFlow: ['1. Deposit 100 tokens when exchange rate = 3.001 tokens/share', '2. shares = 100 / 3.001 = 33 (rounded down from 33.322)', '3. Depositor lost 0.322 shares worth of value', '4. This value stays in vault, inflating share price', '5. Attacker who deposited first benefits from accumulated rounding errors'] },
            });
          }
        }

        // Pattern 3: Fee calculation rounding
        if (/fee|feeRate|performanceFee/i.test(source)) {
          const feeCalc = source.match(/fee\s*=\s*[^;]*\/[^;]*\*[^;]*;|fee\s*=\s*\([^)]*\/[^)]*\)\s*\*/g);
          if (feeCalc) {
            for (const calc of feeCalc) {
              if (/\/.*\*/.test(calc)) {
                findings.push({
                  title: `Fee Calculation — division before multiplication loses precision`,
                  severity: 'medium',
                  contract: `${contract.name} (${file.file})`,
                  evidence: { code: calc },
                  impact: 'Fee calculation divides before multiplying, losing precision. Over millions of transactions, the accumulated rounding error can be significant. In some cases, fees can round to 0 for small amounts, allowing fee-free transactions.',
                  remediation: 'Multiply before dividing in fee calculations. Use higher precision (1e18 base).',
                  poc: { scenario: 'fee = (amount / 10000) * 30 → for amount=1, fee=0. For amount=9999, fee=29 instead of 29.997' },
                });
              }
            }
          }
        }

        // Pattern 4: Reward distribution rounding
        if (/reward|rewardRate|rewardPerToken|accrued/i.test(source)) {
          findings.push({
            title: `Reward Distribution Rounding — small stakers may get 0 rewards`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { hasRewardCalc: true },
            impact: 'Reward per token calculations often divide by total supply. Small stakers may get 0 rewards due to rounding (e.g., reward = 1 wei, totalStaked = 1e18 → rewardPerToken = 0). Attacker can exploit by front-running with a large stake to dilute others\' rewards to 0.',
            remediation: 'Use higher precision for reward accumulators (1e36 instead of 1e18). Accumulate rewards with mulDiv pattern.',
            poc: { scenario: 'rewardPerToken = rewardRate * elapsed / totalSupply → for small totalSupply, rounds to 0' },
          });
        }
      }
    }
    return findings;
  },

  _findDivBeforeMul(body) {
    const vulns = [];
    // Pattern: (x / y) * z or x / y * z
    const re = /\(?(\w+)\s*\/\s*(\w+)\s*\)?\s*\*\s*(\w+)/g;
    let m;
    while ((m = re.exec(body)) !== null) {
      vulns.push({ code: m[0], pattern: `${m[1]} / ${m[2]} * ${m[3]}` });
    }
    // Also: x *= y / z
    const re2 = /(\w+)\s*\*=\s*(\w+)\s*\/\s*(\w+)/g;
    while ((m = re2.exec(body)) !== null) {
      vulns.push({ code: m[0], pattern: `${m[1]} *= ${m[2]} / ${m[3]}` });
    }
    return vulns;
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
