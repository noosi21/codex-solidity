module.exports = {
  name: 'nft-reentrancy',
  aliases: ['erc721-reentrancy', 'erc1155-reentrancy', 'token-callback'],
  severity: 'high',
  description: 'NFT Reentrancy — onERC721Received/onERC1155Received callback enables reentrancy bypassing ETH guards',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: onERC721Received callback during safeTransferFrom
        if (/onERC721Received|IERC721Receiver|ERC721Receiver|safeTransferFrom.*ERC721/i.test(source)) {
          const hasReentrancyGuard = /nonReentrant|_notEntered|_status|_locked|reentrancyGuard/i.test(source);
          const hasStateUpdateBeforeCall = this._checkStateBeforeCallback(source, contract, 'ERC721');

          if (!hasReentrancyGuard || !hasStateUpdateBeforeCall) {
            findings.push({
              title: `ERC721 Callback Reentrancy — onERC721Received triggers during safeTransferFrom`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasERC721Callback: true, hasReentrancyGuard, stateBeforeCall: hasStateUpdateBeforeCall },
              impact: `When the contract receives an ERC721 token via safeTransferFrom, the sender's onERC721Received() hook is called DURING the transfer. If the contract updates state AFTER the transfer, the callback can re-enter before the state update.

This is DIFFERENT from ETH reentrancy — standard reentrancy guards may not cover NFT callbacks. Attackers can:
1. Use NFT transfer as the reentrancy trigger instead of ETH transfer
2. Bypass guards that only check for ETH reentrancy
3. Re-enter through NFT callback to manipulate state

Real impact: If NFT ownership determines access/balance/rewards, re-entering during callback can claim rewards multiple times or manipulate ownership-based logic.`,
              remediation: 'Apply ReentrancyGuard to ALL functions that interact with ERC721/ERC1155. Update state BEFORE safe transfers. Consider using transferFrom() instead of safeTransferFrom() when the receiver is trusted.',
              poc: {
                attackFlow: [
                  '1. Contract has: stakeNFT() → updates balance AFTER safeTransferFrom',
                  '2. Attacker calls stakeNFT() with their NFT',
                  '3. safeTransferFrom triggers attacker.onERC721Received()',
                  '4. In callback, attacker calls stakeNFT() AGAIN with same NFT (if not yet recorded)',
                  '5. Or: attacker calls claimReward() — balance not yet updated, reads stale state',
                  '6. Double reward claim or balance manipulation',
                ],
              },
            });
          }
        }

        // Pattern 2: ERC1155 callback — onERC1155Received
        if (/onERC1155Received|IERC1155Receiver|ERC1155Receiver|safeTransferFrom.*ERC1155|safeBatchTransferFrom/i.test(source)) {
          findings.push({
            title: `ERC1155 Callback Reentrancy — onERC1155Received enables reentrancy`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { hasERC1155Callback: true },
            impact: 'ERC1155 safeTransferFrom and safeBatchTransferFrom trigger onERC1155Received callbacks. Same reentrancy risk as ERC721 but worse: batch transfers trigger MULTIPLE callbacks (one per token type), giving the attacker multiple re-entry points in a single transaction.',
            remediation: 'Use ReentrancyGuard. Update state before safe transfers. Process all state changes before any external calls.',
            poc: { attackFlow: ['1. Attacker calls function that receives ERC1155 batch', '2. onERC1155BatchReceived triggers for each token', '3. Each callback can re-enter the contract', '4. Multiple re-entry points in single transaction'] },
          });
        }

        // Pattern 3: NFT as collateral — callback during liquidation
        if (/collateral.*NFT|NFT.*collateral|liquidat.*NFT|nftCollateral/i.test(source) || (/ERC721/i.test(source) && /liquidat|borrow|lend/i.test(source))) {
          findings.push({
            title: `NFT Collateral Reentrancy — callback during NFT collateral seizure`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { nftCollateral: true },
            impact: 'Contract uses NFTs as collateral. When liquidating/seizing NFT collateral, the safeTransferFrom triggers the borrower\'s onERC721Received callback. If state is not updated before the transfer, borrower can re-enter to: (1) borrow more against already-seized collateral, (2) prevent liquidation by reverting in callback, (3) manipulate health factor calculations.',
            remediation: 'Mark collateral as seized BEFORE transferring the NFT. Use ReentrancyGuard. Consider using transferFrom() instead of safeTransferFrom() for liquidations.',
            poc: { attackFlow: ['1. Borrower\'s NFT collateral being liquidated', '2. Contract calls safeTransferFrom to seize NFT', '3. Borrower\'s onERC721Received callback fires', '4. Borrower re-enters: borrows more against NFT (not yet marked as seized)', '5. NFT transferred but extra debt also issued — protocol insolvent'] },
          });
        }

        // Pattern 4: NFT minting with callback — ERC721A/ERC721Batch
        if (/ERC721A|_mint|batchMint|mintBatch/i.test(source)) {
          findings.push({
            title: `NFT Batch Mint — callback during mint can enable reentrancy`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { hasBatchMint: true },
            impact: 'Batch NFT minting (ERC721A style) may trigger callbacks for each minted token. If the mint function updates state (e.g., totalSupply, balances) after minting, callback reentrancy can exploit stale state.',
            remediation: 'Update all state before individual token transfers in batch mint. Use ReentrancyGuard.',
            poc: { scenario: 'Batch mint 10 NFTs → callback on each → re-enter during mint → claim rewards based on stale balance' },
          });
        }
      }
    }
    return findings;
  },

  _checkStateBeforeCallback(source, contract, tokenType) {
    // Heuristic: check if functions that receive NFTs update state before external calls
    const receiveFns = contract.functions?.filter(fn =>
      /onERC721Received|onERC1155Received|receiveNFT|stakeNFT|depositNFT/i.test(fn.name)
    ) || [];

    for (const fn of receiveFns) {
      const fnBody = this._extractFunctionBody(source, fn.name);
      if (!fnBody) continue;
      // Simple check: if there's a state update after an external call
      const hasExternalCall = /\.call|\.transfer|\.send|safeTransfer/i.test(fnBody);
      if (hasExternalCall) {
        const callIdx = fnBody.search(/\.call|\.transfer|\.send|safeTransfer/);
        const stateUpdateAfter = fnBody.substring(callIdx).match(/balances|totalSupply|_balances|ownerOf|_owners/i);
        if (stateUpdateAfter) return false;
      }
    }
    return true;
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
