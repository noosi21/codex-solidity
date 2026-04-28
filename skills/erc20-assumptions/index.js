module.exports = {
  name: 'erc20-assumptions',
  aliases: ['fee-on-transfer', 'rebasing-token', 'deflationary-token'],
  severity: 'high',
  description: 'ERC20 Assumptions — fee-on-transfer, rebasing, and non-standard tokens break accounting',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Token transfer amount assumed to equal received amount
        const transferFns = contract.functions?.filter(fn => {
          const body = this._extractFunctionBody(source, fn.name);
          return body && /\.(transfer|transferFrom)\s*\(/i.test(body);
        }) || [];

        for (const fn of transferFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const usesSafeTransfer = /safeTransfer|safeTransferFrom/i.test(fnBody);
          const checksBalanceBefore = /balanceBefore|balBefore|_balanceBefore/i.test(fnBody);
          const checksBalanceAfter = /balanceAfter|balAfter|_balanceAfter|after.*balance.*before|diff/i.test(fnBody);

          // Extract the transfer amount variable
          const transferMatch = fnBody.match(/\.(?:safe)?(?:Transfer|transferFrom)\s*\(\s*[^,]+,\s*[^,]+,\s*(\w+)\s*\)/);
          const amountVar = transferMatch ? transferMatch[1] : null;

          // Check if amount is used directly for accounting without verifying received amount
          const usesAmountForAccounting = amountVar && new RegExp(`(balances|balanceOf|deposits|totalDeposits|shares|totalSupply)\\s*\\[?[^=]*\\]?\\s*[+=]\\s*${amountVar}`).test(fnBody);

          if (!usesSafeTransfer && !checksBalanceAfter && usesAmountForAccounting) {
            findings.push({
              title: `Fee-on-Token Breaks Accounting — ${fn.name}() assumes transfer amount == received amount`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: {
                amountVar,
                accountingPattern: `${amountVar} used directly for balance update`,
                noBalanceDiffCheck: true,
                code: fnBody.match(new RegExp(`(balances|balanceOf|deposits|totalDeposits|shares|totalSupply)[^;]*${amountVar}[^;]*;`))?.[0],
              },
              impact: `Contract assumes that when ${amountVar} tokens are transferred, exactly ${amountVar} tokens are received. This is FALSE for fee-on-transfer tokens (e.g., SafeMoon, STA) where a fee is deducted during transfer. If the token charges a 10% fee:
- User deposits 100 tokens, contract receives 90 (10% fee)
- Contract credits user for 100 tokens in accounting
- User withdraws 100 tokens → contract only has 90
- Contract becomes insolvent — other users' funds stolen to cover the gap

For rebasing tokens (e.g., AMPL, stETH), balances change automatically without transfers — all share calculations break.`,
              remediation: `Before and after token transfer, check balance difference:\nuint256 balBefore = token.balanceOf(address(this));\ntoken.safeTransferFrom(msg.sender, address(this), amount);\nuint256 received = token.balanceOf(address(this)) - balBefore;\nrequire(received >= minAmount, "INSUFFICIENT_RECEIVED");\n// Use 'received' for accounting, NOT 'amount'`,
              poc: {
                attackFlow: [
                  `1. Attacker deposits 100 fee-on-transfer tokens`,
                  `2. Transfer deducts 10% fee → contract receives only 90`,
                  `3. Contract credits attacker for 100 in accounting`,
                  `4. Attacker withdraws 100 → contract short 10 tokens`,
                  `5. Next user tries to withdraw — contract insolvent`,
                  `6. OR: attacker deposits, gets credited MORE than received, repeatedly withdraws profit`,
                ],
                feeOnTransferExample: {
                  deposit: '100 tokens',
                  fee: '10%',
                  received: '90 tokens',
                  credited: '100 tokens',
                  deficit: '10 tokens per deposit — compounds with multiple users',
                },
              },
            });
          }
        }

        // Pattern 2: Rebasing token incompatibility
        if (/balanceOf/i.test(source) && /share|shares|exchangeRate|convert/i.test(source)) {
          const hasRebaseProtection = /rebase|rebasing|elastic|ameliorated/i.test(source);
          if (!hasRebaseProtection) {
            findings.push({
              title: `Rebasing Token Incompatibility — share calculations break with elastic supply`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasShares: true, noRebaseProtection: true },
              impact: 'If the contract accepts rebasing tokens (AMPL, stETH), the balanceOf can change without any transfer. Share calculations based on fixed exchange rates become incorrect. Users may be unable to withdraw or can withdraw more than their fair share.',
              remediation: 'Use wrapped versions of rebasing tokens (wAMPL, wstETH). Or track shares separately from token balances.',
              poc: { scenario: 'User deposits 100 AMPL → gets 100 shares. AMPL rebase +10% → balanceOf now 110. Exchange rate calculation gives user 110 tokens for 100 shares. But totalSupply also increased → other users shortchanged.' },
            });
          }
        }

        // Pattern 3: USDT-style non-standard approve
        if (/approve\s*\(/i.test(source) && !/safeApprove|forceApprove|SafeERC20/i.test(source)) {
          findings.push({
            title: `Non-standard ERC20 approve — USDT requires setting to 0 first`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { usesApprove: true, noSafeApprove: true },
            impact: 'USDT and some other tokens require approve to be set to 0 before setting to a new value. Calling approve(spender, newAmount) when current allowance is non-zero will revert. This can DOS all token operations.',
            remediation: 'Use SafeERC20 safeApprove() or forceApprove(). Or: approve(spender, 0) then approve(spender, newAmount).',
            poc: { attackFlow: ['1. Contract calls token.approve(spender, 100)', '2. Later calls token.approve(spender, 200)', '3. USDT reverts — must set to 0 first', '4. All token operations blocked — DOS'] },
          });
        }

        // Pattern 4: Missing decimals() consideration
        if (/decimals\s*\(\)/i.test(source)) {
          const hardcodedDecimals = /1e18|10\s*\*\s*18|1_000_000_000_000_000_000/i.test(source) && !/decimals\s*\(\)/i.test(source);
          if (hardcodedDecimals) {
            findings.push({
              title: `Hardcoded 18 decimals — breaks with non-18 decimal tokens (USDC=6, WBTC=8)`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hardcodedDecimals: true },
              impact: 'Contract assumes all tokens have 18 decimals. USDC has 6, WBTC has 8, some tokens have 0. Calculations using hardcoded 1e18 will be wildly incorrect for these tokens — users can deposit small amounts and withdraw large amounts.',
              remediation: 'Use token.decimals() for calculations. Or only accept tokens with 18 decimals and enforce this.',
              poc: { scenario: 'Token has 6 decimals. Contract calculates shares = amount / 1e18. User deposits 1 USDC (1e6) → shares = 0 → loses deposit' },
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
