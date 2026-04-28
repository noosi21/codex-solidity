module.exports = {
  name: 'read-only-reentrancy',
  aliases: ['readonly-reentrancy', 'view-reentrancy'],
  severity: 'critical',
  description: 'Read-Only Reentrancy — view functions return stale data during callback, oracle reads wrong value',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Contract has external call + view function used as oracle
        const hasExternalCall = /\.call\s*\(|\.transfer\s*\(|\.send\s*\(/i.test(source);
        const hasViewFunctions = contract.functions?.some(fn => fn.visibility === 'view' || fn.visibility === 'pure') || false;
        const hasStateReaders = /getPrice|getBalance|totalAssets|convertToShares|convertToAssets|getReserves|balanceOf|exchangeRate|getAmountOut/i.test(source);

        if (hasExternalCall && hasViewFunctions && hasStateReaders) {
          // Find specific view functions that read state potentially stale during callback
          const viewFns = contract.functions?.filter(fn => {
            if (fn.visibility !== 'view' && fn.visibility !== 'pure') return false;
            const fnBody = this._extractFunctionBody(source, fn.name);
            if (!fnBody) return false;
            return /totalAssets|balanceOf|exchangeRate|getPrice|getReserves|convertTo|shares|totalSupply|reserve/i.test(fnBody);
          }) || [];

          // Find external call functions that don't update state before call
          const externalCallFns = contract.functions?.filter(fn => {
            const fnBody = this._extractFunctionBody(source, fn.name);
            if (!fnBody) return false;
            return /\.call\s*\(|\.transfer\s*\(|\.send\s*\(/i.test(fnBody);
          }) || [];

          if (viewFns.length > 0 && externalCallFns.length > 0) {
            findings.push({
              title: `Read-Only Reentrancy — view functions read stale state during external call callback`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                viewFunctions: viewFns.map(f => f.name),
                externalCallFunctions: externalCallFns.map(f => f.name),
                risk: 'External call triggers callback → callback reads view function → stale state returned',
              },
              impact: `This is the most MISSED vulnerability in DeFi. When ${externalCallFns[0]?.name}() makes an external call, the receiver gets control BEFORE state is fully updated. During this callback, if the receiver calls any view function (${viewFns.map(f => f.name).join(', ')}), it returns STALE data.

Attack scenario:
1. Vault.withdraw() sends ETH to attacker contract BEFORE updating totalAssets
2. Attacker's receive() callback calls Vault.totalAssets() — returns PRE-withdraw value
3. Another protocol uses Vault.totalAssets() as oracle → reads inflated value
4. Attacker borrows against inflated collateral value
5. After callback returns, totalAssets is updated — but attacker already extracted value
6. Protocol left with bad debt — other users lose funds

This has caused $100M+ in losses (Curve pool exploits, Balancer incidents).`,
              remediation: 'Add reentrancy guard to ALL functions including view functions that read state. Update state BEFORE external calls (CEI pattern). Use a "locked" flag that view functions check. Consider adding _beforeTokenTransfer hook that sets a reentrancy lock.',
              poc: {
                attackFlow: [
                  `1. Attacker deposits into vault, gets shares`,
                  `2. Attacker calls ${externalCallFns[0]?.name || 'withdraw'}() — vault sends ETH before updating totalAssets`,
                  '3. During ETH transfer, attacker callback fires',
                  `4. Attacker calls ${viewFns[0]?.name || 'totalAssets'}() — returns stale (inflated) value`,
                  '5. Lending protocol uses this as oracle → attacker borrows max against inflated collateral',
                  '6. Callback returns, vault updates totalAssets — but attacker already extracted value',
                  '7. Lending protocol has bad debt — other depositors lose funds',
                ],
                realIncidents: ['Curve reentrancy ($70M+)', 'Balancer read-only reentrancy', 'Yearn vault exploits'],
              },
            });
          }
        }

        // Pattern 2: ERC4626 vault with callback + view totalAssets
        if (/ERC4626|Vault/i.test(source) && /totalAssets/i.test(source)) {
          const withdrawBody = contract.functions?.filter(fn => /withdraw|redeem/i.test(fn.name))
            .map(fn => this._extractFunctionBody(source, fn.name))
            .find(b => b && /\.call|\.transfer|\.send/i.test(b));

          if (withdrawBody) {
            const totalAssetsIsView = contract.functions?.some(fn =>
              fn.name === 'totalAssets' && fn.visibility === 'view'
            );

            if (totalAssetsIsView) {
              findings.push({
                title: `ERC4626 Read-Only Reentrancy — totalAssets() view + external call in withdraw`,
                severity: 'critical',
                contract: `${contract.name} (${file.file})`,
                evidence: { totalAssetsIsView: true, withdrawHasExternalCall: true },
                impact: 'totalAssets() is a view function that can be called during the withdraw callback. Other protocols (lending, DEX) may use totalAssets() as an oracle. During the callback, totalAssets returns the pre-withdrawal (inflated) value. Attacker exploits this to borrow more than they should from downstream protocols.',
                remediation: 'Make totalAssets() check a reentrancy lock. Or use a cached totalAssets that updates before the external call. Add nonReentrant modifier to view functions.',
                poc: { attackFlow: ['1. Withdraw triggers ETH transfer', '2. Callback reads totalAssets() — stale/inflated', '3. Downstream protocol uses stale value', '4. Attacker extracts value from downstream'] },
              });
            }
          }
        }

        // Pattern 3: Callback-enabled token (ERC777/ERC721) + view state reader
        if (/ERC777|tokensReceived|IERC777|onERC721Received|ERC721Receiver/i.test(source)) {
          const viewReaders = contract.functions?.filter(fn =>
            (fn.visibility === 'view') && /balance|total|price|rate|share/i.test(fn.name)
          ) || [];
          if (viewReaders.length > 0) {
            findings.push({
              title: `Token Callback + View Functions — ERC777/ERC721 callback enables read-only reentrancy`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasCallback: true, viewReaders: viewReaders.map(f => f.name) },
              impact: `Contract accepts ERC777/ERC721 tokens which trigger callbacks during transfer. View functions ${viewReaders.map(f => f.name).join(', ')} can return stale data during these callbacks. Downstream protocols reading these view functions get incorrect values.`,
              remediation: 'Add reentrancy guards that also protect view functions. Cache state before token transfers.',
              poc: { scenario: 'ERC777 tokensReceived callback during deposit → view function returns stale state' },
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
