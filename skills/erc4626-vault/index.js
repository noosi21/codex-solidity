module.exports = {
  name: 'erc4626-vault',
  aliases: ['vault', 'erc-4626', 'tokenized-vault'],
  severity: 'critical',
  description: 'ERC4626 Vault — inflation attack, withdrawal rounding, share price manipulation in tokenized vaults',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const isVault = /ERC4626|Vault|IERC4626|deposit|withdraw|mint|redeem|totalAssets|convertToShares|convertToAssets|previewDeposit|previewWithdraw/i.test(source);
        if (!isVault) continue;

        // Pattern 1: No minimum shares / inflation attack
        const hasMinShares = /MINIMUM_LIQUIDITY|minimumShares|minShares|_MINIMUM|totalSupply\s*>\s*0.*require|require.*totalSupply\s*>\s*0/i.test(source);
        if (!hasMinShares) {
          findings.push({
            title: `ERC4626 Inflation Attack — no minimum shares, first depositor can steal subsequent deposits`,
            severity: 'critical',
            contract: `${contract.name} (${file.file})`,
            evidence: { noMinimumShares: true, hasDeposit: /function\s+deposit/i.test(source), hasMint: /function\s+mint/i.test(source) },
            impact: `Classic inflation attack on ${contract.name}:
1. Attacker deposits 1 wei → gets 1 share (1:1 exchange rate)
2. Attacker donates 100 ETH directly to vault (no shares minted)
3. Now 1 share = 100.0000001 ETH (exchange rate massively inflated)
4. Victim deposits 99.999 ETH → gets 0 shares (rounded down: 99.999/100.0000001 ≈ 0.9999 → 0)
5. Victim's ETH is in vault but they own 0 shares — CANNOT withdraw
6. Attacker redeems 1 share → gets ~200 ETH (their 100 + victim's 100)
7. Victim has 0 shares, 0 withdrawal rights — TOTAL LOSS`,
            remediation: 'Mint minimum shares to address(0) on first deposit (like Uniswap MINIMUM_LIQUIDITY). Or require totalSupply > 0 before accepting deposits. Use OpenZeppelin ERC4626 with _initialConvertToShares override.',
            poc: {
              attackFlow: [
                '1. Attacker calls deposit(1, attacker) → gets 1 share',
                '2. Attacker sends 100 ETH directly to vault address',
                '3. totalAssets = 100.0000001 ETH, totalSupply = 1 share',
                '4. convertToShares(99.99 ETH) = 99.99 * 1 / 100.0000001 = 0 (rounded down)',
                '5. Victim calls deposit(99.99 ETH, victim) → gets 0 shares',
                '6. Vault balance = 200 ETH, attacker shares = 1, victim shares = 0',
                '7. Attacker redeems 1 share → gets all 200 ETH',
                '8. Victim lost 99.99 ETH — cannot withdraw with 0 shares',
              ],
              mathProof: { deposit: '1 wei', donation: '100 ETH', victimDeposit: '99.99 ETH', victimShares: '0 (rounded down)', attackerProfit: '~200 ETH' },
            },
          });
        }

        // Pattern 2: Withdrawal rounding — attacker extracts dust per withdrawal
        const hasRoundingProtection = /previewRedeem|previewWithdraw|_withdraw|convertToShares.*\+.*totalSupply|ceil/i.test(source);
        if (!hasRoundingProtection && /redeem|withdraw/i.test(source)) {
          findings.push({
            title: `Withdrawal Rounding — attacker extracts dust per redeem, scales across pool`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noRoundingProtection: true },
            impact: `Vault share→asset conversion rounds DOWN on withdrawal. Attacker can:
1. Deposit small amount, get N shares
2. Redeem N shares → receives slightly LESS than fair value (rounding down)
3. But the rounding error (1-2 wei) stays in the vault
4. Repeat thousands of times — each iteration the vault "keeps" dust
5. Over time, vault accumulates significant "orphan" assets
6. If vault has a sweep function, attacker (or owner) can extract accumulated dust

Conversely, if deposit rounds DOWN on shares, attacker can deposit and get slightly fewer shares than deserved — the "missing" shares accumulate as value for existing shareholders.`,
            remediation: 'Use ceil division for withdrawals (round up in favor of vault). Use OpenZeppelin ERC4626 _decimalsOffset() pattern. Add rounding direction comments per ERC4626 spec.',
            poc: { attackFlow: ['1. Attacker deposits 1000 wei, gets 999 shares (rounding)', '2. Redeems 999 shares, gets 999 wei back', '3. 1 wei remains in vault as "dust"', '4. Repeat 10000 times → 10000 wei accumulated', '5. Attacker or owner sweeps dust'] },
          });
        }

        // Pattern 3: Missing preview functions — ERC4626 spec violation
        const hasPreviewDeposit = /previewDeposit/i.test(source);
        const hasPreviewRedeem = /previewRedeem/i.test(source);
        const hasPreviewMint = /previewMint/i.test(source);
        const hasPreviewWithdraw = /previewWithdraw/i.test(source);

        const missingPreviews = [];
        if (/function\s+deposit/i.test(source) && !hasPreviewDeposit) missingPreviews.push('previewDeposit');
        if (/function\s+redeem/i.test(source) && !hasPreviewRedeem) missingPreviews.push('previewRedeem');
        if (/function\s+mint/i.test(source) && !hasPreviewMint) missingPreviews.push('previewMint');
        if (/function\s+withdraw/i.test(source) && !hasPreviewWithdraw) missingPreviews.push('previewWithdraw');

        if (missingPreviews.length > 0) {
          findings.push({
            title: `Missing ERC4626 Preview Functions — ${missingPreviews.join(', ')}`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { missing: missingPreviews },
            impact: `Vault is missing ERC4626-required preview functions: ${missingPreviews.join(', ')}. Without preview functions, integrators (aggregators, routers, UIs) cannot accurately estimate shares/assets. This leads to: (1) users getting fewer shares than expected, (2) slippage checks failing, (3) MEV bots exploiting the uncertainty.`,
            remediation: 'Implement all ERC4626 preview functions. They should return the exact same values as the actual functions but without state changes.',
            poc: { note: 'Spec compliance issue — affects integrator safety' },
          });
        }

        // Pattern 4: Vault with fee-on-entry/exit but no fee accounting
        if (/fee|feeRate|performanceFee|managementFee|exitFee|entryFee/i.test(source)) {
          const hasFeeAccouting = /feesCollected|collectedFees|_fees|feeRecipient|accruedFee/i.test(source);
          if (!hasFeeAccouting) {
            findings.push({
              title: `Vault Fee Without Proper Accounting — fees may be silently lost`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasFee: true, noFeeAccounting: true },
              impact: 'Vault charges fees but does not properly account for them. Fees may be: (1) lost in rounding, (2) absorbed by share price instead of being distributed to fee recipient, (3) bypassed by direct transfers.',
              remediation: 'Track fees in a separate state variable. Distribute fees to designated recipient. Ensure fee calculation is transparent and cannot be bypassed.',
              poc: { scenario: 'Performance fee charged but not distributed — value absorbed by share price, fee recipient gets nothing' },
            });
          }
        }

        // Pattern 5: Vault asset that can be frozen/blocked
        if (/asset\s*\(\)/i.test(source) || /IERC20\s+public\s+asset/i.test(source)) {
          const assetMatch = source.match(/asset\s*=\s*(\w+)|IERC20\s+(?:public\s+)?(?:immutable\s+)?asset\s*=\s*(\w+)/i);
          const assetName = assetMatch ? (assetMatch[1] || assetMatch[2]) : 'unknown';
          findings.push({
            title: `Vault Depends on External Asset — ${assetName} can be frozen/blacklisted`,
            severity: 'low',
            contract: `${contract.name} (${file.file})`,
            evidence: { asset: assetName },
            impact: `Vault holds ${assetName} tokens. If the asset implements blacklist/freeze functionality (USDC, USDT), the vault can be frozen. If the vault address is blacklisted, ALL users lose access to their funds — the vault cannot transfer the asset out.`,
            remediation: 'Consider supporting multiple asset types. Add emergency withdrawal mechanism. Document blacklist risk in README.',
            poc: { scenario: 'USDC blacklists vault address → vault cannot transfer USDC → all users locked out' },
          });
        }
      }
    }
    return findings;
  },
};
