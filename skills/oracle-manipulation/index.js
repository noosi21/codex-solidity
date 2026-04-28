module.exports = {
  name: 'oracle-manipulation',
  aliases: ['oracle', 'price-oracle', 'bad-oracle'],
  severity: 'high',
  description: 'Oracle Manipulation — exploit stale/fake prices to drain pools and steal collateral',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Single oracle source — no fallback
        const oracleRefs = this._findOracleReferences(source);
        if (oracleRefs.length > 0) {
          const hasMultipleOracles = oracleRefs.length >= 2;
          const hasChainlink = /chainlink|AggregatorV3Interface|latestRoundData/i.test(source);
          const hasTWAP = /twap|time.?weighted|cumulative/i.test(source);
          const hasStalenessCheck = /stale|updatedAt|roundId|answeredInRound|_timeout|heartbeat/i.test(source);

          if (!hasMultipleOracles && !hasTWAP) {
            findings.push({
              title: `Single Oracle Dependency — no price source redundancy`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                oracleRefs,
                hasChainlink,
                hasTWAP,
                hasStalenessCheck,
                risk: hasChainlink && !hasStalenessCheck ? 'Chainlink without staleness check' : 'Single oracle source',
              },
              impact: hasChainlink && !hasStalenessCheck
                ? 'Contract uses Chainlink oracle but does NOT check for stale/offline prices. If Chainlink goes offline, the last known price is used indefinitely. Attacker can: (1) exploit stale price after market moves significantly, (2) borrow against overvalued collateral, (3) drain lending pools using outdated prices.'
                : 'Contract relies on a single price source. If that oracle is manipulated, goes offline, or returns incorrect data, ALL financial calculations are wrong. Attacker can drain pools by exploiting the incorrect price.',
              remediation: hasChainlink
                ? 'Add staleness checks: verify updatedAt is recent, check roundId > 0, check answeredInRound > 0. Add fallback oracle. Set max price deviation threshold.'
                : 'Use Chainlink with staleness checks + TWAP as fallback. Never rely on a single oracle. Add circuit breaker for price deviations >10%.',
              poc: {
                attackFlow: hasChainlink && !hasStalenessCheck ? [
                  '1. Monitor Chainlink oracle for the target pair',
                  '2. Wait for oracle to go offline or lag behind market',
                  '3. While oracle shows ETH=$2000, market price drops to $1500',
                  '4. Deposit ETH as collateral at $2000 valuation',
                  '5. Borrow maximum against overvalued collateral',
                  '6. When oracle updates, position is undercollateralized but attacker already extracted value',
                  '7. Protocol absorbs bad debt — other users lose funds',
                ] : [
                  '1. Identify the single oracle source',
                  '2. Find a way to manipulate it (flash loan, front-run update, etc.)',
                  '3. Exploit manipulated price for profit',
                  '4. Drain pool before price corrects',
                ],
              },
            });
          }

          // Chainlink staleness check missing
          if (hasChainlink && !hasStalenessCheck) {
            findings.push({
              title: `Chainlink Oracle — no staleness/out-of-range checks`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                pattern: 'latestRoundData() without checking updatedAt/roundId',
                code: this._extractChainlinkUsage(source),
              },
              impact: 'Chainlink can return stale data during L2 sequencer downtime, oracle downtime, or during price feed updates. Without checking updatedAt, the contract accepts arbitrarily old prices. On L2s (Arbitrum, Optimism), sequencer downtime means the oracle freezes — attacker can exploit the frozen price to drain all pools.',
              remediation: 'After calling latestRoundData(), check: (1) roundId > 0, (2) answeredInRound >= roundId, (3) updatedAt >= block.timestamp - maxStaleness, (4) price > 0. On L2s, also check sequencer uptime.',
              poc: {
                attackFlow: [
                  '1. L2 sequencer goes down (Arbitrum/Optimism)',
                  '2. Chainlink oracle freezes at last known price',
                  '3. Market moves significantly while oracle is frozen',
                  '4. Attacker uses frozen price to borrow against overvalued collateral',
                  '5. Sequencer comes back, oracle updates, position undercollateralized',
                  '6. Protocol takes bad debt loss — users pay the price',
                ],
              },
            });
          }
        }

        // Pattern 2: On-chain price from DEX reserves (manipulatable)
        const dexPricePatterns = this._findDexPricePatterns(source);
        if (dexPricePatterns.length > 0) {
          findings.push({
            title: `DEX Reserve-Based Pricing — flash-loan manipulable`,
            severity: 'critical',
            contract: `${contract.name} (${file.file})`,
            evidence: { patterns: dexPricePatterns },
            impact: 'Price is calculated from DEX reserves which can be manipulated in a single transaction via flash loan. Attacker borrows massive amount, swaps to distort reserves, then exploits the distorted price to drain the protocol. TWAP must be used to resist this attack — spot prices are trivially manipulable.',
            remediation: 'Replace spot price with TWAP over multiple blocks. Use Chainlink as primary oracle. Add maximum price deviation checks per block.',
            poc: {
              attackFlow: [
                '1. Flash borrow 10,000 ETH from Aave/dYdX',
                '2. Swap all 10,000 ETH for tokenX in the pool',
                '3. Pool reserves now show tokenX is 10x cheaper than reality',
                '4. Contract reads this manipulated price',
                '5. Attacker deposits cheap tokenX as collateral (overvalued by manipulated price)',
                '6. Borrows maximum ETH against it',
                '7. Repays flash loan from borrowed ETH',
                '8. Keeps excess collateral value — protocol drained',
              ],
            },
          });
        }

        // Pattern 3: Hardcoded prices
        const hardcodedPrices = this._findHardcodedPrices(source);
        if (hardcodedPrices.length > 0) {
          findings.push({
            title: `Hardcoded Price — no oracle, static value`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { hardcodedPrices },
            impact: 'Price is hardcoded in the contract. It cannot adapt to market changes. Once the real market price diverges from the hardcoded value, arbitrageurs will drain the contract. This is guaranteed fund loss over time.',
            remediation: 'Use a live price oracle (Chainlink, TWAP). Never hardcode prices for production contracts.',
            poc: { attackFlow: ['1. Market price diverges from hardcoded price', '2. Attacker deposits token that is undervalued by hardcoded price', '3. Borrows token that is overvalued', '4. Profit from the difference — guaranteed arbitrage'] },
          });
        }

        // Pattern 4: Oracle price not validated (zero, negative, extreme)
        if (oracleRefs.length > 0) {
          const hasPriceValidation = /require.*price\s*>\s*0|require.*answer\s*>\s*0|price\s*!=\s*0|price\s*>\s*minPrice|maxPrice/i.test(source);
          if (!hasPriceValidation) {
            findings.push({
              title: `Oracle Price Not Validated — zero/extreme price accepted`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { noPriceCheck: true, oracleRefs },
              impact: 'Oracle price is used without validation. If oracle returns 0 (during update/maintenance), all calculations divide by zero or treat collateral as worthless. If oracle returns extreme value, attacker can exploit it. Both scenarios lead to fund drain.',
              remediation: 'Validate oracle price: require(price > minPrice && price < maxPrice). Check for zero. Add circuit breaker for >50% price change in single block.',
              poc: { attackFlow: ['1. Oracle returns 0 during maintenance', '2. Contract calculates collateral value as 0', '3. All positions appear undercollateralized', '4. Liquidations cascade — users lose funds'] },
            });
          }
        }
      }
    }
    return findings;
  },

  _findOracleReferences(source) {
    const refs = [];
    if (/Chainlink|AggregatorV3Interface|latestRoundData/i.test(source)) refs.push('Chainlink');
    if (/UniswapV3Twap|IUniswapV3Pool|observe/i.test(source)) refs.push('UniswapV3 TWAP');
    if (/getAmountsOut|getAmountOut|reserve[01]/i.test(source)) refs.push('DEX spot price');
    if (/BandProtocol|StdReference/i.test(source)) refs.push('Band Protocol');
    if (/Tellor|ITellor/i.test(source)) refs.push('Tellor');
    if (/API3|IApi3Server/i.test(source)) refs.push('API3');
    if (/Pyth|IPyth/i.test(source)) refs.push('Pyth');
    if (/getPrice|priceFeed|oracle/i.test(source)) refs.push('Custom oracle');
    return refs;
  },

  _findDexPricePatterns(source) {
    const patterns = [];
    if (/price\s*=\s*reserve[01]\s*\*\s*[^/]*\/\s*reserve[01]/i.test(source)) patterns.push('Price = reserve0 * X / reserve1');
    if (/getAmountsOut|getAmountOut/i.test(source)) patterns.push('getAmountsOut (spot price)');
    if (/getReserves/i.test(source)) patterns.push('Direct getReserves() call');
    if (/token0Balance.*token1Balance/i.test(source)) patterns.push('Direct token balance ratio');
    return patterns;
  },

  _findHardcodedPrices(source) {
    const prices = [];
    const re = /price\s*=\s*(\d+)|rate\s*=\s*(\d+)|VALUE\s*=\s*(\d+).*ether|PRICE\s*=\s*(\d+)/gi;
    let m;
    while ((m = re.exec(source)) !== null) {
      const val = m[1] || m[2] || m[3] || m[4];
      if (val && parseInt(val) > 0) prices.push({ match: m[0], value: val, line: source.substring(0, m.index).split('\n').length });
    }
    return prices;
  },

  _extractChainlinkUsage(source) {
    const match = source.match(/latestRoundData\s*\([^)]*\)[^;]{0,200}/);
    return match ? match[0] : 'latestRoundData() usage found';
  },
};
