module.exports = {
  name: 'eip-2612-permit',
  aliases: ['permit', 'eip-2612', 'gasless-approval', 'daipermit'],
  severity: 'high',
  description: 'EIP-2612 Permit — permit replay across chains, expired permit acceptance, signature validation bypass',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const hasPermit = /permit|PERMIT_TYPEHASH|eip712|EIP712|domainSeparator|_hashTypedDataV4/i.test(source);
        if (!hasPermit) continue;

        // Pattern 1: Permit replay across chains
        const hasChainIdInDomain = /block\.chainid|chainId|CHAIN_ID/i.test(source);
        if (!hasChainIdInDomain) {
          findings.push({
            title: `Permit Replay Across Chains — domain separator doesn't include chain ID`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noChainIdInDomain: true },
            impact: `EIP-712 domain separator does not include chain ID. A permit signed for Chain A is also valid on Chain B (if the contract is deployed at the same address). Attacker can:
1. Get a valid permit on Ethereum (user signs approve for 100 tokens)
2. Replay the same permit on Arbitrum/Optimism/other L2 where contract exists at same address
3. Permit is valid — tokens approved on L2 without user's consent
4. Attacker transfers user's L2 tokens`,
            remediation: 'Include block.chainid in the domain separator. Handle chain ID changes during forks: if (block.chainid != cachedChainId) { return _buildDomainSeparator(); }',
            poc: {
              attackFlow: [
                '1. User signs permit on Ethereum: approve(spender, 100)',
                '2. Domain separator same on all chains (no chainId)',
                '3. Attacker replays permit on Arbitrum',
                '4. Tokens approved on Arbitrum without user consent',
                '5. Attacker transfers user\'s Arbitrum tokens',
              ],
            },
          });
        }

        // Pattern 2: Expired permits accepted
        const hasDeadlineCheck = /deadline|expiry|require.*block\.timestamp.*deadline/i.test(source);
        if (!hasDeadlineCheck) {
          findings.push({
            title: `No Permit Deadline — permits never expire, can be used anytime`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { noDeadline: true },
            impact: 'Permit function does not check a deadline parameter. Once a user signs a permit, it can be submitted at any time in the future. An old permit that the user no longer intends can still be used to approve token transfers.',
            remediation: 'Add deadline parameter to permit(): require(block.timestamp <= deadline, "PERMIT_EXPIRED")',
            poc: { attackFlow: ['1. User signs permit 6 months ago but never submits', '2. User no longer wants to approve the spender', '3. Attacker obtains the old signature', '4. Submits permit — no deadline check → approved', '5. Attacker transfers user\'s tokens'] },
          });
        }

        // Pattern 3: Permit with s-value not checked (malleability)
        const hasSValueCheck = /s\s*<=\s*0x7F|secp256k1|ECDSA|s.*half/i.test(source);
        if (!hasSValueCheck && /ecrecover/i.test(source)) {
          findings.push({
            title: `Permit Signature Malleability — ecrecover without s-value upper bound`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noSValueCheck: true, usesEcrecover: true },
            impact: 'Permit uses ecrecover without checking s-value upper bound. For any valid signature (r, s, v), the malleable pair (r, n-s, v^1) is also valid. Attacker can use the malleable signature to call permit() a second time with a "different" signature, doubling the approval.',
            remediation: 'Use OpenZeppelin ECDSA library which checks s <= secp256k1n/2. Or add: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)',
            poc: { attackFlow: ['1. User signs permit approving 100 tokens', '2. Spender calls permit(r, s, v) → approved', '3. Attacker computes (r, n-s, v^1) from observed signature', '4. Calls permit(r, n-s, v^1) → "different" signature, same approval', '5. Approval doubled to 200 tokens'] },
          });
        }

        // Pattern 4: Permit for zero address
        const hasZeroAddressCheck = /owner\s*!=\s*address\s*\(\s*0\s*\)|require.*owner.*!.*0x0/i.test(source);
        if (!hasZeroAddressCheck) {
          findings.push({
            title: `Permit Accepts address(0) as owner — potential signature collision`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { noZeroAddressCheck: true },
            impact: 'Permit function does not check that owner != address(0). If ecrecover returns address(0) (invalid signature), the function continues. Since allowances[address(0)] is a valid storage location, this could lead to unexpected behavior or be used in combination with other bugs.',
            remediation: 'Add: require(owner != address(0), "INVALID_OWNER") after ecrecover.',
            poc: { scenario: 'Invalid signature → ecrecover returns address(0) → function continues with owner=0x0' },
          });
        }

        // Pattern 5: Nonce not incremented — permit can be replayed
        const hasNonceIncrement = /nonce|nonces|_nonces|\.nonce\s*[+=]|nonces\[.*\]\+\+/i.test(source);
        if (!hasNonceIncrement) {
          findings.push({
            title: `Permit Without Nonce — same permit can be used multiple times`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noNonce: true },
            impact: 'Permit function does not use or increment a nonce. The same permit signature can be submitted multiple times. If the permit sets approval to a fixed amount (not max), each submission overwrites the previous approval — not directly harmful. But if used for other actions (e.g., permitAndCall), the action can be repeated.',
            remediation: 'Include nonces[owner]++ in permit function. Include nonce in the signed message hash.',
            poc: { attackFlow: ['1. User signs permit with nonce 0', '2. Permit submitted → nonce should increment to 1', '3. Without nonce increment, same permit valid again', '4. Attacker resubmits same permit'] },
          });
        }
      }
    }
    return findings;
  },
};
