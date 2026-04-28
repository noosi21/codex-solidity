module.exports = {
  name: 'front-running',
  aliases: ['mev', 'sandwich', 'slippage'],
  severity: 'high',
  description: 'Front-Running / MEV — sandwich attacks, slippage exploitation, no minimum output protection',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Swap without minimum output (no slippage protection)
        const swapFns = contract.functions?.filter(fn =>
          /swap|exchange|trade|buy|sell|convert/i.test(fn.name)
        ) || [];

        for (const fn of swapFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const hasMinOut = /minAmountOut|minOut|minReceived|deadline|amountOutMin|slippage|minReturn/i.test(fnBody) ||
            fn.params?.includes('minAmount') || fn.params?.includes('minOut') || fn.params?.includes('deadline');

          if (!hasMinOut) {
            findings.push({
              title: `Sandwich Attack — ${fn.name}() has no slippage protection`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: {
                function: fn.name,
                params: fn.params,
                noSlippageProtection: true,
                code: this._extractVulnerableSnippet(fnBody),
              },
              impact: `User calls ${fn.name}() without specifying minimum output. MEV bot sees the pending transaction, front-runs with a large swap to move the price, then back-runs to profit from the price impact. The user receives significantly less tokens than the fair market price. On high-value swaps, this can cost users 5-30% of their trade value. On mainnet, EVERY unprotected swap WILL be sandwiched.`,
              remediation: `Add minAmountOut parameter to ${fn.name}(). Calculate expected output and set minAmountOut to expectedOutput * (1 - slippageTolerance). Add deadline parameter to prevent stale transaction execution.`,
              poc: {
                attackFlow: [
                  `1. User submits ${fn.name}() to swap 100 ETH for tokenX`,
                  '2. MEV bot sees pending tx in mempool',
                  '3. Bot front-runs: buys tokenX with 100 ETH → price increases',
                  '4. User tx executes: gets fewer tokenX due to inflated price',
                  '5. Bot back-runs: sells tokenX → price returns to normal',
                  '6. Bot profits the difference (user\'s loss)',
                  '7. User lost 5-30% of trade value to sandwich attack',
                ],
                estimatedLoss: '5-30% of swap value on mainnet',
                fix: `function ${fn.name}(..., uint256 minAmountOut, uint256 deadline) {
    require(block.timestamp <= deadline, "EXPIRED");
    uint256 amountOut = _swap(...);
    require(amountOut >= minAmountOut, "INSUFFICIENT_OUTPUT");
}`,
              },
            });
          }
        }

        // Pattern 2: No deadline check — stale transaction execution
        const timeSensitiveFns = contract.functions?.filter(fn =>
          /swap|withdraw|claim|redeem|borrow|repay|liquidate/i.test(fn.name)
        ) || [];

        for (const fn of timeSensitiveFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const hasDeadline = /deadline|expiry|expireTime|validUntil/i.test(fn.params || '') || /block\.timestamp.*deadline|deadline.*block\.timestamp/i.test(fnBody);

          if (!hasDeadline && /swap|exchange/i.test(fn.name)) {
            // Already caught in Pattern 1, skip duplicate
            continue;
          }

          if (!hasDeadline && /liquidate/i.test(fn.name)) {
            findings.push({
              title: `Stale Liquidation — ${fn.name}() has no deadline`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noDeadline: true },
              impact: 'Liquidation transactions can be delayed in the mempool. If a position becomes healthy before the liquidation executes, the liquidator still forces a liquidation — causing unnecessary loss to the borrower. MEV searchers can also hold liquidation txs until they become most profitable.',
              remediation: 'Add deadline parameter to liquidation functions. Check block.timestamp <= deadline.',
              poc: { attackFlow: ['1. Borrower\'s position is briefly underwater', '2. Liquidation tx submitted', '3. Borrower adds collateral, position becomes healthy', '4. But stale liquidation tx still executes', '5. Borrower unfairly liquidated'] },
            });
          }
        }

        // Pattern 3: Predictable randomness — front-run lottery/reward distribution
        if (/lottery|raffle|reward|prize|winner|random|rand/i.test(source)) {
          const usesBlockHash = /blockhash|block\.hash|block\.difficulty|block\.timestamp/i.test(source);
          const usesUnsafeRand = /keccak256.*block\.|keccak256.*timestamp|keccak256.*difficulty/i.test(source);

          if (usesBlockHash || usesUnsafeRand) {
            findings.push({
              title: `Predictable Randomness — miners/validators can front-run outcomes`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                pattern: usesBlockHash ? 'blockhash() used as entropy' : 'keccak256(block.timestamp/difficulty) used as entropy',
                code: source.match(/blockhash\s*\([^)]+\)|keccak256\s*\([^)]*block\.[^)]+\)/)?.[0],
              },
              impact: 'Randomness derived from block properties is predictable. Miners/validators can: (1) choose which block to mine to get favorable randomness, (2) front-run lottery entries, (3) always win. If prizes involve token rewards, attacker can drain the reward pool with certainty.',
              remediation: 'Use Chainlink VRF for verifiable randomness. Never use block.timestamp, block.difficulty, or blockhash as entropy sources.',
              poc: {
                attackFlow: [
                  '1. Attacker (miner/validator) sees pending lottery entries',
                  '2. Attacker calculates which block properties produce winning outcome',
                  '3. Attacker includes their own entry with favorable timing',
                  '4. Attacker wins lottery with 100% certainty',
                  '5. Reward pool drained by repeated wins',
                ],
              },
            });
          }
        }

        // Pattern 4: ERC777/ERC721 callback reentrancy (different from standard reentrancy)
        if (/ERC777|IERC777|tokensReceived|ERC721Receiver|onERC721Received/i.test(source)) {
          findings.push({
            title: `ERC777/ERC721 Callback Reentrancy — token transfer triggers attacker callback`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { pattern: 'ERC777 tokensReceived or ERC721 onERC721Received callback' },
            impact: 'When the contract sends ERC777 tokens, the recipient\'s tokensReceived() hook is called DURING the transfer. If state is not updated before the transfer, the recipient can re-enter. Same for ERC721 safe transfers. This is a variant of reentrancy that bypasses standard ETH reentrancy guards.',
            remediation: 'Use ReentrancyGuard on ALL functions that interact with ERC777/ERC721. Update state BEFORE token transfers. Consider using ERC20 instead of ERC777.',
            poc: { attackFlow: ['1. Attacker deploys contract implementing tokensReceived()', '2. Attacker deposits tokens into target', '3. Attacker calls withdraw()', '4. Target transfers tokens → triggers attacker.tokensReceived()', '5. tokensReceived() re-enters withdraw() before balance update', '6. Double withdrawal — funds drained'] },
          });
        }

        // Pattern 5: First-depositor advantage / inflation attack
        if (/shares|balanceOf|totalSupply|_totalSupply/i.test(source) && /deposit|mint|stake/i.test(source)) {
          const hasFirstDepositorProtection = /_totalSupply\s*>\s*0|totalSupply\s*>\s*0|minimumShares|MINIMUM_LIQUIDITY|_MINIMUM/i.test(source);
          if (!hasFirstDepositorProtection) {
            findings.push({
              title: `First-Depositor / Inflation Attack — attacker can steal subsequent deposits`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                hasShares: true,
                noProtection: true,
                pattern: 'No minimum shares or totalSupply > 0 check on first deposit',
              },
              impact: `First depositor can donate tokens to the contract BEFORE anyone else deposits, inflating the share price. When victim deposits, they receive 0 shares (due to rounding) but their tokens are added to the pool. Attacker then redeems their shares, stealing the victim's deposit. Victim gets NOTHING back.`,
              remediation: 'Add minimum shares requirement on deposit. Lock MINIMUM_LIQUIDITY tokens on first deposit (like Uniswap). Check totalSupply > 0 before calculating shares.',
              poc: {
                attackFlow: [
                  '1. Attacker deposits 1 wei → gets 1 share',
                  '2. Attacker donates 100 ETH directly to contract (no shares minted)',
                  '3. Now 1 share = 100.0000001 ETH',
                  '4. Victim deposits 100 ETH → gets 0 shares (rounded down)',
                  '5. Victim\'s 100 ETH is in pool but they own 0 shares',
                  '6. Attacker redeems 1 share → gets 200 ETH (their 100 + victim\'s 100)',
                  '7. Victim has 0 shares, cannot withdraw — total loss',
                ],
              },
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

  _extractVulnerableSnippet(body) {
    if (!body) return '';
    return body.split('\n').filter(l => l.trim()).slice(0, 12).join('\n');
  },
};
