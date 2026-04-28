module.exports = {
  name: 'l2-sequencer',
  aliases: ['sequencer', 'l2', 'arbitrum', 'optimism'],
  severity: 'high',
  description: 'L2 Sequencer — sequencer downtime freezes oracle, enables lending pool drain on Arbitrum/Optimism',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const isLending = /borrow|collateral|liquidat|healthFactor|lend/i.test(source);
        const usesChainlink = /Chainlink|AggregatorV3Interface|latestRoundData/i.test(source);
        const hasSequencerCheck = /sequencer|SEQUENCER|sequencerUptimeFeed|isUp/i.test(source);

        // Pattern 1: Chainlink oracle on L2 without sequencer uptime check
        if (usesChainlink && !hasSequencerCheck) {
          findings.push({
            title: `L2 Chainlink Without Sequencer Check — oracle freezes during downtime`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { usesChainlink: true, noSequencerCheck: true },
            impact: `Contract uses Chainlink oracle on L2 (Arbitrum/Optimism) but does NOT check the sequencer uptime feed. When the L2 sequencer goes down:
1. Chainlink oracle freezes — returns last known price indefinitely
2. Contract continues using stale price as if it's current
3. Market price moves significantly while oracle is frozen
4. Attacker exploits the price discrepancy:
   - If real price dropped: deposit overvalued collateral, borrow max
   - If real price rose: borrow undervalued assets
5. When sequencer comes back, oracle updates — positions are underwater
6. Protocol absorbs bad debt — depositors lose funds

This has happened multiple times on Arbitrum during sequencer downtime.`,
            remediation: 'Add Chainlink Sequencer Uptime Feed check: AggregatorV3Interface sequencerFeed; (uint80 roundId, int256 answer, ...) = sequencerFeed.latestRoundData(); require(answer == 0, "SEQUENCER_DOWN"); require(block.timestamp - startedAt > GRACE_PERIOD, "GRACE_PERIOD_NOT_OVER");',
            poc: {
              attackFlow: [
                '1. Arbitrum sequencer goes down',
                '2. Chainlink oracle freezes at ETH=$2000',
                '3. Real market: ETH drops to $1500',
                '4. Attacker deposits ETH at $2000 valuation',
                '5. Borrows maximum USDC against overvalued collateral',
                '6. Sequencer comes back, oracle updates to $1500',
                '7. Position underwater but attacker already extracted USDC',
                '8. Protocol has bad debt — depositors lose',
              ],
            },
          });
        }

        // Pattern 2: Lending protocol without sequencer grace period
        if (isLending && !hasSequencerCheck) {
          findings.push({
            title: `Lending on L2 Without Sequencer Protection — instant liquidation after downtime`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { isLending: true, noSequencerCheck: true },
            impact: `Lending protocol on L2 has no sequencer downtime protection. When sequencer comes back after downtime:
1. Oracle updates to new (possibly very different) prices
2. Many positions instantly become underwater
3. Liquidators immediately liquidate all underwater positions
4. Borrowers have NO time to add collateral — they were unable to transact during downtime
5. Mass liquidations → borrowers lose collateral at unfavorable prices

This is especially damaging for borrowers who wanted to add collateral during downtime but couldn't because the sequencer was down.`,
            remediation: 'Implement grace period after sequencer recovery: no liquidations allowed for X blocks after sequencer comes back. Use Chainlink L2 Sequencer Uptime Feed.',
            poc: { attackFlow: ['1. Sequencer goes down for 2 hours', '2. ETH price drops 15% during downtime', '3. Borrowers cannot add collateral (sequencer down)', '4. Sequencer comes back, oracle updates', '5. Liquidators instantly liquidate all underwater positions', '6. Borrowers lose collateral with no chance to react'] },
          });
        }

        // Pattern 3: L2-specific bridge delay not accounted for
        if (/bridge|withdraw|exit/i.test(source) && !/challengePeriod|challenge_period|withdrawalDelay|exitDelay/i.test(source)) {
          findings.push({
            title: `No Bridge Withdrawal Delay — funds can be stolen in challenge period`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { noChallengePeriod: true },
            impact: 'Bridge withdrawal function has no challenge period or delay. On optimistic rollups (Arbitrum, Optimism), withdrawals should have a challenge period (typically 7 days) to allow validators to dispute fraudulent withdrawals. Without this, fraudulent withdrawals cannot be contested.',
            remediation: 'Implement a challenge period for bridge withdrawals. Use the L2 bridge standard withdrawal flow with proof submission.',
            poc: { scenario: 'Fraudulent withdrawal submitted → no challenge period → funds immediately released → cannot be disputed' },
          });
        }

        // Pattern 4: L1→L2 message without confirmation
        if (/inbox|outbox|crossChainSender|canonicalCrossChain/i.test(source)) {
          findings.push({
            title: `Cross-Chain Message Without Confirmation — replay or spoofing risk`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { hasCrossChain: true },
            impact: 'Contract processes cross-chain messages but may not properly verify the sender or that the message was actually sent on the source chain. Attacker can forge messages to claim they deposited/bridged assets when they didn\'t.',
            remediation: 'Use the canonical L1↔L2 message bridge (Arbitrum Inbox/Outbox, Optimism CanonicalBridge). Verify message sender via crossChainContext. Never trust msg.sender for cross-chain calls.',
            poc: { attackFlow: ['1. Attacker calls handleMessage() directly', '2. Claims to have deposited 100 ETH on L1', '3. No verification of actual L1 deposit', '4. 100 ETH released on L2 — stolen'] },
          });
        }
      }
    }
    return findings;
  },
};
