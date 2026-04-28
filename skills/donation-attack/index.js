module.exports = {
  name: 'donation-attack',
  aliases: ['donation', 'direct-transfer', 'gift-attack'],
  severity: 'high',
  description: 'Donation Attack — donate tokens directly to inflate share price, victim gets 0 shares',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const hasShares = /shares|totalSupply|convertToShares|convertToAssets|balanceOf.*shares/i.test(source);
        const hasDeposit = /deposit|mint|stake|enter/i.test(source);
        if (!hasShares || !hasDeposit) continue;

        // Pattern 1: No protection against direct token transfers inflating share price
        const hasDonationProtection = /MINIMUM_LIQUIDITY|minimumShares|_MINIMUM|totalSupply\s*>\s*0.*require|virtualShares|offset|_decimalsOffset/i.test(source);
        const usesTotalAssets = /totalAssets|address\s*\(\s*this\s*\)\s*\.balance|IERC20.*balanceOf\s*\(\s*address\s*\(\s*this\s*\)/i.test(source);

        if (!hasDonationProtection && usesTotalAssets) {
          findings.push({
            title: `Donation Attack — direct token transfer inflates share price, victim gets 0 shares`,
            severity: 'critical',
            contract: `${contract.name} (${file.file})`,
            evidence: { noDonationProtection: true, usesTotalAssets: true },
            impact: `Attacker can donate tokens directly to the vault contract (bypassing deposit). This increases totalAssets without minting shares, inflating the share price. When a victim deposits, they receive 0 shares (rounded down) but their tokens are added to the pool. Attacker then redeems their shares, capturing the victim's deposit.

Attack steps:
1. Attacker deposits 1 wei → gets 1 share (1:1 rate)
2. Attacker transfers 100 ETH directly to vault address
3. totalAssets jumps to ~100 ETH, totalSupply still 1 share
4. Share price = 100 ETH per share
5. Victim deposits 99 ETH → shares = 99/100 = 0 (rounded down)
6. Victim's 99 ETH is in vault but they own 0 shares
7. Attacker redeems 1 share → gets all ~199 ETH
8. Victim has 0 shares → CANNOT withdraw — total loss`,
            remediation: 'Implement OpenZeppelin ERC4626 with _decimalsOffset(). Mint MINIMUM_LIQUIDITY shares to address(0) on first deposit. Use virtual shares/assets offset pattern. Or track "accounted" assets separately from actual balance.',
            poc: {
              attackFlow: [
                '1. Attacker: deposit(1 wei) → 1 share',
                '2. Attacker: transfer(100 ETH) directly to vault',
                '3. Share price: 100 ETH/share',
                '4. Victim: deposit(99 ETH) → 0 shares (99/100 rounds down)',
                '5. Attacker: redeem(1) → gets all ~199 ETH',
                '6. Victim: 0 shares, 0 withdrawal rights',
              ],
              mathProof: { attackerDeposit: '1 wei', donation: '100 ETH', sharePrice: '100 ETH/share', victimDeposit: '99 ETH', victimShares: '0', attackerProfit: '~199 ETH' },
            },
          });
        }

        // Pattern 2: Vault with receive() that doesn't account for direct ETH
        if (contract.hasReceive || contract.hasFallback) {
          const receiveBody = this._extractReceiveBody(source);
          if (receiveBody && !/emit|Deposit|accountedFor|_totalAssets/i.test(receiveBody)) {
            findings.push({
              title: `receive() Accepts Unaccounted ETH — donation attack vector`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasReceive: true, noAccounting: true },
              impact: 'Contract has receive() that accepts ETH but does not account for it in totalAssets. Direct ETH transfers inflate the share price without minting shares, enabling the donation/inflation attack.',
              remediation: 'Either revert on unexpected ETH transfers, or track all incoming ETH in a separate accountedBalance variable.',
              poc: { attackFlow: ['1. Attacker sends ETH directly to contract via transfer', '2. ETH received but not tracked in totalAssets', '3. Share price inflated', '4. Victim deposits → gets fewer shares than entitled'] },
            });
          }
        }

        // Pattern 3: Fee-on-transfer token donation — double inflation
        if (/feeOnTransfer|deflationary|safeTransfer/i.test(source)) {
          findings.push({
            title: `Fee-on-Transfer Token Donation — attacker donates less than expected, extra inflation`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { hasFeeToken: true },
            impact: 'If the vault accepts fee-on-transfer tokens, a donation of 100 tokens results in only 90 tokens received (10% fee). The share price is calculated based on the 90 received, but the attacker only "spent" 90 net tokens. This creates a discrepancy that can be exploited.',
            remediation: 'Track actual received amount (balanceBefore vs balanceAfter) instead of the transfer amount.',
            poc: { scenario: 'Donate 100 fee-on-transfer tokens → 90 received → share price based on 90 → attacker spent only 90 net' },
          });
        }
      }
    }
    return findings;
  },

  _extractReceiveBody(source) {
    const receiveRe = /receive\s*\(\s*\)\s*(?:external\s+)?payable\s*\{/g;
    const match = receiveRe.exec(source);
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
