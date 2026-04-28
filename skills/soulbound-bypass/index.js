module.exports = {
  name: 'soulbound-bypass',
  aliases: ['sbt', 'soulbound', 'non-transferable'],
  severity: 'medium',
  description: 'Soulbound Token Bypass — transfer restriction bypass via loopholes in SBT implementation',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const isSBT = /soulbound|SBT|non.?transfer|non.?transferable|_soulbound|isBound|bound/i.test(source) ||
          (/ERC721/i.test(source) && /transfer.*revert|transferFrom.*revert|cannot.*transfer|not.*transferable/i.test(source));
        if (!isSBT) continue;

        // Pattern 1: transferFrom blocked but safeTransferFrom not
        const blocksTransferFrom = /transferFrom\s*\([^)]*\)[^{]*revert|require.*!\s*transfer|transfer.*disabled|transfer.*blocked/i.test(source);
        const blocksSafeTransferFrom = /safeTransferFrom\s*\([^)]*\)[^{]*revert|safeTransfer.*disabled/i.test(source);

        if (blocksTransferFrom && !blocksSafeTransferFrom) {
          findings.push({
            title: `SBT Bypass — safeTransferFrom() not blocked, only transferFrom() is`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { transferFromBlocked: true, safeTransferFromNotBlocked: true },
            impact: 'Soulbound token blocks transferFrom() but NOT safeTransferFrom(). Attacker can call safeTransferFrom() to transfer the "non-transferable" token. This completely defeats the soulbound property — identity tokens, credentials, and reputation tokens can be sold/transferred.',
            remediation: 'Override BOTH transferFrom() and safeTransferFrom() (all overloads). Add a universal _beforeTokenTransfer hook that checks transferability.',
            poc: { attackFlow: ['1. SBT blocks: transferFrom() → revert', '2. Attacker calls: safeTransferFrom(from, to, tokenId)', '3. safeTransferFrom NOT blocked → transfer succeeds', '4. "Soulbound" token transferred — property broken'] },
          });
        }

        // Pattern 2: Only _transfer blocked, but burn allows transfer-like behavior
        const hasBurn = /burn|_burn/i.test(source);
        const burnIsPublic = contract.functions?.some(fn => /burn/i.test(fn.name) && fn.visibility === 'public' && fn.visibility !== 'internal') || false;
        if (hasBurn && burnIsPublic) {
          findings.push({
            title: `SBT Burn — public burn() allows destroying soulbound tokens`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { publicBurn: true },
            impact: 'Soulbound token has a public burn() function. While this doesn\'t allow transfer, it allows: (1) destroying identity/credential tokens, (2) bypassing requirements that check for SBT ownership, (3) re-minting if the contract allows it. If the SBT represents a credential, burning it removes the credential — potentially to re-obtain it under different terms.',
            remediation: 'Restrict burn() to only the contract owner or specific authorized addresses. Or make SBTs truly permanent (no burn).',
            poc: { attackFlow: ['1. SBT represents "KYC verified" credential', '2. Attacker burns their SBT', '3. Re-applies for KYC with different identity', '4. Gets new SBT — bypasses one-credential-per-person rule'] },
          });
        }

        // Pattern 3: Approval not blocked — spender can "hold" the token
        const blocksApproval = /approve.*revert|setApprovalForAll.*revert|approval.*disabled/i.test(source);
        if (!blocksApproval) {
          findings.push({
            title: `SBT Approval Not Blocked — tokens can be "held" by approved spender`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { approvalNotBlocked: true },
            impact: 'Soulbound token blocks transfers but NOT approvals. While the approved address cannot transfer the token, they can: (1) use it as collateral in protocols that check approvals, (2) effectively "own" the token for protocol interactions, (3) create a market for SBT "access" without actual transfer.',
            remediation: 'Override approve() and setApprovalForAll() to revert. Add _beforeTokenTransfer hook that blocks all approvals.',
            poc: { scenario: 'User approves marketplace for SBT → marketplace can list/interact with SBT even though it can\'t be transferred' },
          });
        }

        // Pattern 4: _beforeTokenTransfer only checks msg.sender, not actual from/to
        if (/beforeTokenTransfer|_beforeTokenTransfer/i.test(source)) {
          const beforeTransferBody = source.match(/_beforeTokenTransfer\s*\([^)]*\)[^{]*\{[^}]*\}/)?.[0];
          if (beforeTransferBody && /from\s*!=\s*address\s*\(\s*0\s*\)/i.test(beforeTransferBody) && !/to\s*!=\s*address\s*\(\s*0\s*\)/i.test(beforeTransferBody)) {
            findings.push({
              title: `SBT Mint Bypass — _beforeTokenTransfer only blocks from!=0, allows re-minting`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { incompleteCheck: true },
              impact: '_beforeTokenTransfer only blocks transfers (from != address(0)) but doesn\'t check mints (from == address(0)). If the mint function is public, anyone can mint duplicate SBTs, creating multiple copies of a "unique" soulbound token.',
              remediation: 'Add mint access control. Track which addresses have already received each SBT type. Limit supply per address.',
              poc: { attackFlow: ['1. SBT has public mint function', '2. _beforeTokenTransfer only blocks from!=0 (transfers)', '3. Attacker mints the same SBT multiple times', '4. Multiple copies of "unique" soulbound token exist'] },
            });
          }
        }
      }
    }
    return findings;
  },
};
