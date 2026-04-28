module.exports = {
  name: 'amm-math',
  aliases: ['amm', 'constant-product', 'swap-math'],
  severity: 'high',
  description: 'AMM Math — constant product invariant violations, swap fee bypass, reserve manipulation',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const isAMM = /swap|addLiquidity|removeLiquidity|getAmountOut|getAmountIn|reserve|kValue|constantProduct|pair/i.test(source);
        if (!isAMM) continue;

        // Pattern 1: No k invariant check after swap
        const hasKCheck = /require.*k|require.*reserve0.*reserve1|k\s*>=|_k\s*>=|invariant|sync/i.test(source);
        if (!hasKCheck && /swap/i.test(source)) {
          findings.push({
            title: `No K-Invariant Check — swap can drain reserves without maintaining constant product`,
            severity: 'critical',
            contract: `${contract.name} (${file.file})`,
            evidence: { noKCheck: true },
            impact: 'AMM swap function does not verify that k (reserve0 * reserve1) is maintained after the swap. Without this check, an attacker can craft a swap that takes more tokens out than the constant product formula allows, directly draining pool reserves. Every swap should verify: newReserve0 * newReserve1 >= oldReserve0 * oldReserve1.',
            remediation: 'Add k-invariant check after every swap: require(reserve0 * reserve1 >= kLast, "K"). Or use Uniswap V2 verified swap math.',
            poc: { attackFlow: ['1. Pool has 100 ETH + 100 tokenX (k=10000)', '2. Attacker swaps 1 ETH for tokenX', '3. Without k check, contract gives 99 tokenX (should be ~1)', '4. Pool now has 101 ETH + 1 tokenX (k=101)', '5. k dropped from 10000 to 101 — massive value extracted', '6. Repeat until pool empty'] },
          });
        }

        // Pattern 2: Fee bypass — fee not deducted before swap calculation
        const hasFeeDeduction = /fee|swapFee|protocolFee|_fee|feeRate/i.test(source);
        if (hasFeeDeduction) {
          for (const fn of contract.functions || []) {
            if (!/swap/i.test(fn.name)) continue;
            const fnBody = this._extractFunctionBody(source, fn.name);
            if (!fnBody) continue;

            const feeBeforeCalc = /amountIn.*fee|amountWithFee|input.*\(.*1\s*-\s*fee|input.*\*.*\(.*1000\s*-\s*fee/i.test(fnBody);
            if (!feeBeforeCalc) {
              findings.push({
                title: `Swap Fee Bypass — fee not deducted before amount calculation in ${fn.name}()`,
                severity: 'high',
                contract: `${contract.name} (${file.file})`,
                function: fn.name,
                evidence: { feeNotDeductedBeforeCalc: true },
                impact: 'Swap fee is not properly deducted before calculating output amount. Attacker can swap without paying the fee, effectively getting a better rate than intended. Over many swaps, this extracts significant value from LP holders.',
                remediation: 'Deduct fee from input amount BEFORE calculating output: amountInWithFee = amountIn * (1000 - fee); output = amountInWithFee * reserveOut / (reserveIn * 1000 + amountInWithFee)',
                poc: { attackFlow: ['1. Fee should be 0.3% (3/1000)', '2. Fee not deducted from input before calculation', '3. Attacker gets output as if fee = 0%', '4. LP holders lose fee revenue', '5. Attacker can arbitrage between this pool and fee-charging pools'] },
              });
            }
          }
        }

        // Pattern 3: addLiquidity without deadline
        const addLiqFns = contract.functions?.filter(fn => /addLiquidity/i.test(fn.name)) || [];
        for (const fn of addLiqFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;
          const hasDeadline = /deadline/i.test(fn.params || '') || /block\.timestamp.*deadline/i.test(fnBody);
          if (!hasDeadline) {
            findings.push({
              title: `addLiquidity without Deadline — MEV sandwich on LP provision`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noDeadline: true },
              impact: 'addLiquidity() has no deadline parameter. Pending transaction can be held in mempool and executed at an unfavorable time. MEV bot can sandwich the LP provision: front-run with a swap to change the ratio, then back-run to restore. LP provider receives fewer LP tokens than expected.',
              remediation: 'Add deadline parameter: require(block.timestamp <= deadline, "EXPIRED")',
              poc: { attackFlow: ['1. User submits addLiquidity(100 ETH, 100 tokenX)', '2. MEV bot front-runs: swaps to change ETH/tokenX ratio', '3. User\'s addLiquidity executes at new ratio → fewer LP tokens', '4. MEV bot back-runs: swaps back to original ratio', '5. User lost value due to ratio manipulation'] },
            });
          }
        }

        // Pattern 4: Minimum LP tokens not enforced
        for (const fn of addLiqFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;
          const hasMinLP = /minLiquidity|minLP|minShares|amountAMin|amountBMin/i.test(fn.params || '') || /require.*liquidity.*>=.*min/i.test(fnBody);
          if (!hasMinLP) {
            findings.push({
              title: `addLiquidity without Minimum LP Tokens — user may receive 0 LP tokens`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noMinLP: true },
              impact: 'addLiquidity() does not enforce minimum LP tokens to be received. Due to rounding or ratio manipulation, user could receive 0 LP tokens while their tokens are added to the pool. User loses their deposit with nothing in return.',
              remediation: 'Add minLiquidity parameter: require(liquidity >= minLiquidity, "INSUFFICIENT_LP")',
              poc: { attackFlow: ['1. User adds liquidity to a pool with skewed ratio', '2. Due to rounding, minted LP tokens = 0', '3. User\'s tokens are in the pool but they have 0 LP', '4. User cannot remove liquidity — total loss'] },
            });
          }
        }

        // Pattern 5: removeLiquidity without minimum output
        const removeLiqFns = contract.functions?.filter(fn => /removeLiquidity/i.test(fn.name)) || [];
        for (const fn of removeLiqFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;
          const hasMinOut = /minAmount|minOut|amountAMin|amountBMin/i.test(fn.params || '') || /require.*amount.*>=.*min/i.test(fnBody);
          if (!hasMinOut) {
            findings.push({
              title: `removeLiquidity without Minimum Output — LP can be sandwiched on withdrawal`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noMinOut: true },
              impact: 'removeLiquidity() does not enforce minimum token amounts. MEV bot can sandwich the withdrawal by manipulating pool ratio before it executes.',
              remediation: 'Add amountAMin and amountBMin parameters with require() checks.',
              poc: { scenario: 'MEV sandwich on LP withdrawal → user receives fewer tokens than fair share' },
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
