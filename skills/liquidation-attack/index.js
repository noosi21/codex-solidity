module.exports = {
  name: 'liquidation-attack',
  aliases: ['liquidation', 'cascade-liquidation', 'bad-debt'],
  severity: 'high',
  description: 'Liquidation Attack — cascade liquidations, bad debt creation, MEV front-running of liquidators',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const isLending = /liquidat|borrow|collateral|healthFactor|health_factor|ltv|collateralFactor/i.test(source);
        if (!isLending) continue;

        // Pattern 1: No liquidation incentive cap — liquidator can take entire position
        const hasIncentiveCap = /liquidationIncentive|liquidationBonus|bonus.*<|incentive.*<|closeFactor.*<|maxLiquidation/i.test(source);
        if (!hasIncentiveCap) {
          findings.push({
            title: `No Liquidation Incentive Cap — liquidator can drain entire position`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noIncentiveCap: true },
            impact: 'Liquidation incentive is not capped. A liquidator could potentially take the entire collateral of an underwater position, leaving the borrower with nothing. Even a small shortfall should only allow liquidating a portion (e.g., 50% close factor) with a reasonable bonus (e.g., 5-10%). Without caps, liquidation becomes predatory — borrowers lose everything for minor shortfalls.',
            remediation: 'Implement close factor (max % of debt that can be liquidated per tx, typically 50%). Cap liquidation bonus (typically 5-10%). Follow Aave/Compound liquidation parameters.',
            poc: { attackFlow: ['1. Borrower has 1 ETH collateral, borrowed 900 USDC', '2. Price drops slightly — position 0.1% underwater', '3. Liquidator repays 900 USDC, takes ALL 1 ETH collateral', '4. Liquidator gets 10%+ bonus on top', '5. Borrower loses everything for a 0.1% shortfall'] },
          });
        }

        // Pattern 2: Flash loan liquidation — no delay between borrow and liquidate
        const hasLiquidationDelay = /liquidationDelay|liquidationGrace|gracePeriod/i.test(source);
        if (!hasLiquidationDelay) {
          findings.push({
            title: `Flash Loan Liquidation — no grace period, borrowers instantly liquidated on price moves`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { noGracePeriod: true },
            impact: 'Borrowers have no grace period when their position becomes underwater. MEV searchers use flash loans to: (1) borrow capital, (2) manipulate price slightly, (3) liquidate underwater positions, (4) profit from liquidation bonus, (5) repay flash loan. All in one atomic transaction. Borrowers cannot react — they are liquidated before they can add collateral.',
            remediation: 'Add a grace period (e.g., 1 hour) where borrowers can add collateral before liquidation is allowed. Or implement gradual liquidation that increases over time.',
            poc: { attackFlow: ['1. Flash borrow 10,000 ETH', '2. Dump on DEX → price drops 2%', '3. Many positions now underwater', '4. Liquidate all positions with flash-borrowed capital', '5. Collect liquidation bonuses', '6. Buy back ETH at lower price', '7. Repay flash loan', '8. Profit from bonuses + price difference'] },
          });
        }

        // Pattern 3: Bad debt not socialized — protocol becomes insolvent
        const hasBadDebtHandling = /badDebt|socializeLoss|shortfall|deficit|insurance|treasury/i.test(source);
        if (!hasBadDebtHandling) {
          findings.push({
            title: `No Bad Debt Handling — protocol becomes insolvent from underwater positions`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noBadDebtHandling: true },
            impact: 'When a position is underwater (debt > collateral value) and not liquidated in time, the protocol has "bad debt." Without a mechanism to handle this: (1) bad debt accumulates, (2) the protocol becomes insolvent, (3) depositors cannot withdraw their funds. This is especially dangerous during flash crashes where many positions become underwater simultaneously.',
            remediation: 'Implement bad debt socialization (loss shared across all depositors). Or maintain a protocol treasury/insurance fund. Auto-liquidate underwater positions. Use real-time health factor monitoring.',
            poc: { attackFlow: ['1. Flash crash — ETH drops 30% in minutes', '2. Many positions underwater simultaneously', '3. Liquidators cannot keep up — positions go deeper underwater', '4. Collateral < debt → bad debt created', '5. No mechanism to absorb bad debt', '6. Protocol insolvent — depositors cannot withdraw'] },
          });
        }

        // Pattern 4: Oracle price used for both collateral and liquidation — same oracle can be manipulated
        const hasSingleOracleForBoth = /getPrice|price.*collateral|price.*borrow/i.test(source) && !/fallback.*oracle|secondary.*oracle/i.test(source);
        if (hasSingleOracleForBoth) {
          findings.push({
            title: `Single Oracle for Collateral & Liquidation — manipulation causes cascade liquidations`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { singleOracle: true },
            impact: 'The same oracle is used for both determining collateral value AND triggering liquidations. If this oracle is manipulated (via flash loan), positions appear underwater even though they are healthy. This triggers cascade liquidations — all borrowers lose their collateral at manipulated prices.',
            remediation: 'Use separate oracles for collateral valuation and liquidation triggers. Add a time delay between oracle price change and liquidation eligibility. Use TWAP for liquidation thresholds.',
            poc: { attackFlow: ['1. Attacker flash-loans to manipulate oracle price', '2. Collateral appears to lose value', '3. All positions appear underwater', '4. Cascade liquidations triggered', '5. Liquidators buy collateral at discount', '6. Oracle price returns to normal', '7. Borrowers lost collateral at manipulated price'] },
          });
        }

        // Pattern 5: Self-liquidation — borrower can liquidate own position
        const liquidateFns = contract.functions?.filter(fn => /liquidat/i.test(fn.name)) || [];
        for (const fn of liquidateFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;
          const preventsSelfLiquidation = /msg\.sender\s*!=\s*borrower|liquidator\s*!=\s*borrower/i.test(fnBody);
          if (!preventsSelfLiquidation) {
            findings.push({
              title: `Self-Liquidation — borrower can liquidate own position for profit`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noSelfLiquidationCheck: true },
              impact: 'A borrower can liquidate their own underwater position and collect the liquidation bonus. This means: (1) the borrower intentionally goes underwater, (2) self-liquidates to get the bonus, (3) effectively reduces their debt at the expense of other depositors. The liquidation bonus is meant to incentivize third-party liquidators, not to subsidize borrowers.',
              remediation: 'Add require(msg.sender != borrower, "CANNOT_SELF_LIQUIDATE") to liquidation function.',
              poc: { attackFlow: ['1. Borrower takes maximum loan', '2. Intentionally allows position to go slightly underwater', '3. Self-liquidates, collecting the liquidation bonus', '4. Net effect: borrower pays less debt than borrowed'] },
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
