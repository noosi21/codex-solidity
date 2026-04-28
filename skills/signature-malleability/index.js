module.exports = {
  name: 'signature-malleability',
  aliases: ['ecdsa-malleability', 'sig-replay', 'signature-replay'],
  severity: 'high',
  description: 'Signature Malleability — ECDSA signatures can be replayed or forged via s-value manipulation',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: ecrecover without s-value check
        if (/ecrecover/i.test(source)) {
          const hasSValueCheck = /s\s*<=\s*0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0|secp256k1.*halfCurveOrder|require.*s.*<=|s.*<.*SECP256K1/i.test(source);
          const usesOpenZeppelinECDSA = /ECDSA|OpenZeppelin.*ecdsa/i.test(source);

          if (!hasSValueCheck && !usesOpenZeppelinECDSA) {
            findings.push({
              title: `ECDSA Signature Malleability — ecrecover without s-value upper bound check`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                usesEcrecover: true,
                noSValueCheck: true,
                noOZECDSA: !usesOpenZeppelinECDSA,
                code: source.match(/ecrecover\s*\([^)]+\)/)?.[0],
              },
              impact: `ECDSA signatures are malleable: for any valid (r, s, v) signature, (r, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s, v^0x1) is ALSO valid. Both signatures verify for the SAME message and signer. This means:
1. **Double-spend:** Attacker observes a valid tx with signature (r,s,v), constructs (r, s', v') and replays the same action
2. **Nonce bypass:** If contract uses signatures as nonce, attacker can use the malleable pair to bypass
3. **Fund drain:** If withdrawal is authorized by signature, attacker can withdraw TWICE using malleable signatures`,
              remediation: 'Use OpenZeppelin ECDSA library which checks s <= secp256k1n/2. Or add: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "ECDSA: invalid s").',
              poc: {
                attackFlow: [
                  '1. User signs message approving withdrawal of 100 tokens',
                  '2. User submits tx with signature (r, s, v)',
                  '3. Contract verifies signature — passes, withdrawal executed',
                  '4. Attacker observes (r, s, v) from mempool/blockchain',
                  '5. Attacker computes s\' = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s',
                  '6. Attacker submits same withdrawal with (r, s\', v^1)',
                  '7. ecrecover returns SAME signer address — signature is "different" but valid',
                  '8. Contract processes withdrawal AGAIN — user drained 2x',
                ],
                mathProof: {
                  original: '(r, s, v) → valid signature for signer X',
                  malleable: '(r, n-s, v⊕1) → ALSO valid signature for signer X',
                  result: 'Two "different" signatures authorize the same action → double spend',
                },
              },
            });
          }
        }

        // Pattern 2: Signature replay — no nonce/used-map check
        const sigFunctions = contract.functions?.filter(fn => {
          const body = this._extractFunctionBody(source, fn.name);
          return body && /ecrecover|verify|signature|_sig|sig/i.test(body);
        }) || [];

        for (const fn of sigFunctions) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const hasNonceCheck = /nonce|used\[|executed\[|_used|isProcessed|_nonce|mapping.*used/i.test(fnBody);
          const hasDeadline = /deadline|expiry|expire/i.test(fn.params || '') || /block\.timestamp.*deadline/i.test(fnBody);

          if (!hasNonceCheck) {
            findings.push({
              title: `Signature Replay — ${fn.name}() has no nonce/used-map, signatures can be replayed`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noNonce: true, noDeadline: !hasDeadline, hasSignature: true },
              impact: `Signatures verified in ${fn.name}() can be replayed indefinitely. Once a valid signature is observed, anyone can call ${fn.name}() with the same signature to repeat the action. If this authorizes fund transfers, attacker can drain all funds by replaying the same signature.`,
              remediation: 'Add a nonce parameter and track used nonces: mapping(bytes32 => bool) public executed; require(!executed[hash], "ALREADY_EXECUTED"); executed[hash] = true;',
              poc: {
                attackFlow: [
                  `1. User signs message authorizing ${fn.name}()`,
                  '2. Function executes successfully',
                  '3. Attacker copies the signature from transaction data',
                  '4. Attacker calls the same function with identical signature',
                  '5. No nonce check — signature is still valid',
                  '6. Action repeated — funds stolen again',
                ],
              },
            });
          }
        }

        // Pattern 3: Using signature for identity without checking signer
        const permitFns = contract.functions?.filter(fn => /permit|approve.*sig|metaTx/i.test(fn.name)) || [];
        for (const fn of permitFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const checksSigner = /require\s*\(\s*signer\s*==|require\s*\(\s*recovered\s*==|signer\s*!=\s*address\s*\(\s*0/i.test(fnBody);
          if (!checksSigner) {
            findings.push({
              title: `Permit/MetaTx — ${fn.name}() doesn't verify signer matches expected address`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noSignerCheck: true },
              impact: 'ecrecover result is not checked against the expected signer. Attacker can forge a signature from any address and the contract will accept it. This completely bypasses the signature verification.',
              remediation: 'Always check: require(signer != address(0) && signer == expectedSigner, "INVALID_SIGNER");',
              poc: { attackFlow: ['1. Attacker generates signature from their own key', '2. ecrecover returns attacker address', '3. No check that signer == expectedSigner', '4. Attacker\'s signature accepted — unauthorized action performed'] },
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
