module.exports = {
  name: 'flash-loan',
  aliases: ['flashloan', 'flash-loan-attack', 'price-manipulation'],
  severity: 'critical',
  description: 'Flash Loan Attack — manipulate prices and drain pools in a single atomic transaction',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Detect DeFi patterns vulnerable to flash loans
        const hasSwap = /swap|exchange|trade|buy|sell/i.test(source);
        const hasLiquidityPool = /addLiquidity|removeLiquidity|liquidity|reserve|pool/i.test(source);
        const hasBorrow = /borrow|loan|flash|lend/i.test(source);
        const hasPriceOracle = /getPrice|price|oracle|rate|value/i.test(source);
        const hasCollateral = /collateral|deposit|margin/i.test(source);
        const usesSpotPrice = /reserve[0-9]*|getAmountsOut|getAmountOut|pairBalance/i.test(source);

        // Pattern 1: Spot price used as oracle without TWAP
        if ((hasSwap || hasLiquidityPool) && usesSpotPrice && !this._hasTWAP(source)) {
          const drainCalc = impactEngine.calcFlashLoanImpact(
            { tokenA: 1000e18, tokenB: 1000e18 },
            { tokenA: 500e18, tokenB: 1500e18 },
            10000e18, true
          );

          findings.push({
            title: `Flash Loan Price Manipulation — spot price used as oracle`,
            severity: 'critical',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              pattern: 'Spot price from DEX used directly without TWAP/time-weighted average',
              indicators: this._findSpotPriceUsage(source),
              noTWAP: true,
            },
            impact: drainCalc.impact + `. An attacker borrows a massive amount via flash loan (no collateral needed), dumps it into the pool to manipulate the price, then exploits the manipulated price to borrow more collateral than warranted, drain lending pools, or arbitrage. The entire attack completes in ONE atomic transaction — no risk to the attacker.`,
            remediation: 'Use TWAP (Time-Weighted Average Price) oracles instead of spot prices. Use Chainlink or multiple oracle sources. Implement price deviation thresholds that reject manipulated prices.',
            poc: {
              type: 'exploit_contract',
              code: impactEngine.generateExploitCode('flashLoan'),
              attackFlow: [
                '1. Borrow 10,000 ETH via flash loan (no collateral, instant)',
                '2. Dump 5,000 ETH into pool → price of other token skyrockets 200%+',
                '3. Use manipulated price as collateral to borrow maximum amount',
                '4. Repay flash loan from the original 10,000 ETH',
                '5. Keep the over-collateralized borrow — profit from price difference',
                '6. All in ONE transaction — attacker risks ZERO capital',
                `7. Estimated price impact: ${drainCalc.priceImpactPercent}%`,
              ],
              drainCalc,
            },
          });
        }

        // Pattern 2: Flash loan + lending protocol without delay
        if (hasBorrow && hasCollateral && !this._hasDelay(source)) {
          findings.push({
            title: `Flash Loan + Instant Borrow — no deposit-to-borrow delay`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              hasBorrow: true,
              hasCollateral: true,
              noDelay: true,
              indicators: this._findBorrowPatterns(source),
            },
            impact: 'Users can deposit collateral and instantly borrow against it in the same transaction via flash loan. This enables: (1) circular borrowing — deposit borrowed funds as collateral to borrow more, (2) governance attacks — flash-borrow governance tokens to pass malicious proposals, (3) drain lending pools by exploiting leverage loops.',
            remediation: 'Add a time delay between deposit and borrowing. Limit borrow power in the same block as deposit. Use flash loan-resistant governance.',
            poc: {
              attackFlow: [
                '1. Flash borrow 10,000 tokenA',
                '2. Deposit as collateral in lending protocol',
                '3. Borrow maximum tokenB against it',
                '4. Swap tokenB for tokenA on DEX',
                '5. Repay flash loan with swapped tokens',
                '6. Keep excess — profit from leverage loop',
              ],
            },
          });
        }

        // Pattern 3: Uniswap V2-style pair with no flash loan callback protection
        if (hasLiquidityPool && /sync|skim|swap/i.test(source)) {
          const hasCallback = /flashLoan|flashBorrow|onFlashLoan|IFlashLoan/i.test(source);
          if (!hasCallback) {
            findings.push({
              title: `Liquidity pool without flash loan callback protection`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasLiquidityPool: true, hasSwap: true, noFlashCallback: true },
              impact: 'Pool allows direct manipulation of reserves via large swaps without flash loan callback mechanism. While this is standard for AMMs, protocols relying on this pool\'s spot price are vulnerable to flash loan manipulation.',
              remediation: 'If this pool is used as a price oracle, implement TWAP. Consider flash loan fees for large swaps.',
              poc: { note: 'Standard AMM behavior — risk is to downstream protocols using spot price' },
            });
          }
        }

        // Pattern 4: Governance with flash-loanable voting tokens
        if (/vote|governance|proposal|castVote/i.test(source) && !this._hasGovernanceDelay(source)) {
          findings.push({
            title: `Flash Loan Governance Attack — no voting delay`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              hasVoting: true,
              noDelay: !this._hasGovernanceDelay(source),
              indicators: this._findGovernancePatterns(source),
            },
            impact: 'Attacker can flash-borrow governance tokens, vote on a malicious proposal, and return tokens in the same transaction. This bypasses the entire governance system — attacker gets full control with zero capital at risk.',
            remediation: 'Implement voting delay (tokens must be held for N blocks before voting). Use snapshot-based voting. Require minimum holding period for proposal creation.',
            poc: {
              attackFlow: [
                '1. Flash borrow governance tokens (e.g., COMP, UNI)',
                '2. Vote on malicious proposal (or create one)',
                '3. Return flash loaned tokens',
                '4. Proposal passes with attacker\'s flash-borrowed votes',
                '5. Attacker executes proposal — drains protocol treasury',
              ],
            },
          });
        }
      }
    }
    return findings;
  },

  _hasTWAP(source) {
    return /twap|time.?weighted|average.*price|cumulative.*price|price[01]Cumulative|observation/i.test(source);
  },

  _hasDelay(source) {
    return /delay|timelock|cooldown|wait.?period|lock.?up|vesting/i.test(source);
  },

  _hasGovernanceDelay(source) {
    return /votingDelay|voting.*delay|snapshot.*delay|hold.*period|min.*hold/i.test(source);
  },

  _findSpotPriceUsage(source) {
    const indicators = [];
    if (/getAmountsOut|getAmountOut/i.test(source)) indicators.push('getAmountsOut (spot price)');
    if (/reserve[01]/i.test(source)) indicators.push('Direct reserve access');
    if (/price\s*=\s*reserve/i.test(source)) indicators.push('Price = reserve ratio');
    if (/getPrice/i.test(source)) indicators.push('getPrice() function');
    return indicators;
  },

  _findBorrowPatterns(source) {
    const indicators = [];
    if (/borrow\s*\(/i.test(source)) indicators.push('borrow() function');
    if (/collateralFactor|ltv|loan.*to.*value/i.test(source)) indicators.push('Collateral factor/LTV');
    if (/deposit.*borrow/i.test(source)) indicators.push('Deposit-then-borrow in same flow');
    return indicators;
  },

  _findGovernancePatterns(source) {
    const indicators = [];
    if (/castVote/i.test(source)) indicators.push('castVote()');
    if (/propose/i.test(source)) indicators.push('propose()');
    if (/getVotes|getCurrentVotes/i.test(source)) indicators.push('Vote counting at current block');
    return indicators;
  },
};
