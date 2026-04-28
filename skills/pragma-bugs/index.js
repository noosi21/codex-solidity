module.exports = {
  name: 'pragma-bugs',
  aliases: ['floating-pragma', 'compiler-bugs', 'solidity-bugs'],
  severity: 'high',
  description: 'Floating Pragma & Known Compiler Bugs — contract may compile with vulnerable compiler version',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    const knownBugs = [
      { version: '<0.4.11', bug: 'Function type can overwrite storage', impact: 'Storage corruption — attacker overwrites critical state vars' },
      { version: '<0.4.12', bug: 'Optimizer bug on constant expressions', impact: 'Incorrect constant values — wrong logic' },
      { version: '<0.4.16', bug: 'Optimizer bug with exponentiation', impact: 'Wrong calculation results' },
      { version: '<0.4.22', bug: 'Constructor not called in inherited contracts', impact: 'Parent constructor skipped — owner never set, access control broken' },
      { version: '<0.4.25', bug: 'Optimizer bug on shift instructions', impact: 'Incorrect bitwise operations — wrong values' },
      { version: '<0.5.0', bug: 'Implicit conversions between bytes types', impact: 'Data corruption in byte operations' },
      { version: '<0.5.7', bug: 'Optimizer bug on redundant mstore', impact: 'Incorrect memory layout' },
      { version: '<0.5.8', bug: 'ABIEncoderV2 — structs & arrays', impact: 'Incorrect encoding/decoding — data corruption' },
      { version: '<0.5.14', bug: 'ABIEncoderV2 — calldata structs', impact: 'Incorrect calldata parsing — wrong function arguments' },
      { version: '<0.5.15', bug: 'Optimizer bug on byte access', impact: 'Wrong byte extraction results' },
      { version: '<0.6.5', bug: 'ABIEncoderV2 — storage structs with nested arrays', impact: 'Storage data corruption' },
      { version: '<0.6.7', bug: 'Optimizer bug on calldata structs', impact: 'Incorrect calldata handling' },
      { version: '<0.6.9', bug: 'ABIEncoderV2 — array of structs in calldata', impact: 'Wrong function inputs — attacker can pass malicious data' },
      { version: '<0.7.1', bug: 'Optimizer bug on self-compounding', impact: 'Wrong arithmetic results' },
      { version: '<0.7.2', bug: 'Yul optimizer bug on word-size access', impact: 'Incorrect memory/storage access' },
      { version: '<0.7.4', bug: 'ABIEncoderV2 — calldata structs with dynamic types', impact: 'Data corruption in decoded calldata' },
      { version: '<0.7.6', bug: 'Yul optimizer bug on unused function parameter', impact: 'Wrong optimization — function behavior altered' },
      { version: '<0.8.0', bug: 'Optimized build with inline assembly', impact: 'Incorrect assembly optimization' },
    ];

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');
      const pragma = file.pragma || '';

      // Pattern 1: Floating pragma (^0.x.x or >=0.x.x)
      if (/pragma\s+solidity\s+[\^>=]/i.test(source) && !/pragma\s+solidity\s+\d+\.\d+\.\d+\s*;/.test(source)) {
        const applicableBugs = knownBugs.filter(b => {
          const vMatch = pragma.match(/(\d+)\.(\d+)\.(\d+)/);
          if (!vMatch) return true;
          return true; // floating pragma means ANY version could be used
        });

        findings.push({
          title: `Floating Pragma — contract can compile with any compiler version`,
          severity: 'high',
          contract: `(${file.file})`,
          evidence: { pragma, floating: true, applicableBugs: applicableBugs.slice(0, 5).map(b => b.bug) },
          impact: `Pragma "${pragma}" allows compiling with ANY matching compiler version. If deployed with a version containing known bugs, the contract may behave incorrectly. Known bugs include: ${applicableBugs.slice(0, 3).map(b => b.bug).join(', ')}. These can cause storage corruption, wrong calculations, or broken access control — all leading to potential fund loss.`,
          remediation: 'Lock the pragma to a specific version: pragma solidity 0.8.19; Choose a version with no known bugs.',
          poc: { risk: 'Contract compiled with vulnerable version → known bug exploited → funds stolen' },
        });
      }

      // Pattern 2: Outdated pragma — check for known bugs
      if (pragma) {
        const vMatch = pragma.match(/(\d+)\.(\d+)\.(\d+)/);
        if (vMatch) {
          const [, major, minor, patch] = vMatch.map(Number);
          const applicable = knownBugs.filter(b => {
            const bv = b.version.match(/<?\s*(\d+)\.(\d+)/);
            if (!bv) return false;
            const [, bm, bn] = bv.map(Number);
            if (b.version.startsWith('<')) return major < bm || (major === bm && minor < bn);
            return major === bm && minor <= bn;
          });

          if (applicable.length > 0) {
            findings.push({
              title: `Known Compiler Bugs — ${applicable.length} bug(s) affect pragma ${pragma}`,
              severity: 'medium',
              contract: `(${file.file})`,
              evidence: { pragma, bugs: applicable.map(b => ({ bug: b.bug, version: b.version, impact: b.impact })) },
              impact: `Compiler version ${pragma} is affected by ${applicable.length} known bug(s). If the contract uses affected features, it may behave incorrectly. Bugs: ${applicable.map(b => b.bug).join(', ')}.`,
              remediation: `Upgrade to Solidity >=0.8.19 (latest stable with no known bugs).`,
              poc: { bugs: applicable },
            });
          }
        }
      }

      // Pattern 3: Using ABIEncoderV2 with old compiler
      if (/ABIEncoderV2|abicoder\s+v2/i.test(source) && /0\.[0-6]\./.test(pragma)) {
        findings.push({
          title: `ABIEncoderV2 with old compiler — struct encoding bugs`,
          severity: 'high',
          contract: `(${file.file})`,
          evidence: { pragma, abiV2: true },
          impact: 'ABIEncoderV2 before 0.7.0 had multiple bugs with struct encoding/decoding. Attacker can craft calldata that decodes incorrectly, bypassing checks or injecting wrong values.',
          remediation: 'Use Solidity >=0.8.0 with ABIEncoderV2 (stable since 0.8.0).',
          poc: { attackFlow: ['1. Contract uses ABIEncoderV2 with Solidity <0.7.0', '2. Attacker crafts calldata with nested struct', '3. Decoding bug causes struct fields to be swapped', '4. Amount field reads as much larger value', '5. Attacker withdraws more than deposited'] },
        });
      }
    }
    return findings;
  },
};
