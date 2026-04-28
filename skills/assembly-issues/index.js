module.exports = {
  name: 'assembly-issues',
  aliases: ['inline-assembly', 'yul-bugs', 'assembly-vuln'],
  severity: 'high',
  description: 'Inline Assembly Vulnerabilities — memory safety, storage collision, and gas issues in Yul/assembly',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Find all assembly blocks
        const assemblyBlocks = this._findAssemblyBlocks(source);

        for (const block of assemblyBlocks) {
          // Pattern 1: assembly extcodesize for address validation (bypassed by constructor)
          if (/extcodesize/i.test(block.code)) {
            findings.push({
              title: `extcodesize Check Bypass — attacker can call from constructor`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: {
                code: block.code.match(/extcodesize[^)]+\)/)?.[0],
                line: block.lineStart,
              },
              impact: 'extcodesize returns 0 for contract addresses during construction (in the constructor). An attacker can call the target function FROM their contract\'s constructor, bypassing the is-contract check. This defeats any "only contracts" or "no contracts" access control based on extcodesize.',
              remediation: 'Use (extcodesize > 0 || tx.origin != msg.sender) to properly detect contracts. Or use EIP-1271 for contract signature validation.',
              poc: {
                attackFlow: [
                  '1. Contract checks extcodesize(msg.sender) > 0 to verify caller is a contract',
                  '2. Attacker deploys malicious contract',
                  '3. In the attacker contract\'s CONSTRUCTOR, calls target function',
                  '4. extcodesize(attacker) == 0 during construction → check fails',
                  '5. Attacker bypasses "only contract" restriction',
                  '6. Protected function called by EOA-equivalent attacker',
                ],
              },
            });
          }

          // Pattern 2: assembly block with mstore/mload — memory safety
          if (/mstore|mload/i.test(block.code)) {
            const usesScratchSpace = /0x00|0x20|0x40|0x60|0x80/i.test(block.code);
            const hasFreeMemoryPointer = /0x40|mload\s*\(\s*0x40/i.test(block.code);

            if (usesScratchSpace && !hasFreeMemoryPointer) {
              findings.push({
                title: `Assembly Uses Scratch Space — may conflict with Solidity memory layout`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                evidence: { code: block.code.match(/mstore\s*\([^)]+\)/g)?.join(', '), line: block.lineStart },
                impact: 'Assembly uses memory slots 0x00-0x60 (scratch space) which Solidity also uses for temporary values. If Solidity code runs after the assembly block, it may overwrite the assembly-written values, or vice versa. This can cause data corruption in function arguments or return values.',
                remediation: 'Use the free memory pointer (0x40) for all memory allocations in assembly. Read mload(0x40) to get free memory, then update it with mstore(0x40, newPointer).',
                poc: { scenario: 'mstore(0x00, value) → Solidity later uses 0x00 for hash temporary → value corrupted' },
              });
            }

            // Check if free memory pointer is updated after allocation
            if (hasFreeMemoryPointer) {
              const allocatesButNoUpdate = /mstore\s*\(\s*0x/i.test(block.code) &&
                !/mstore\s*\(\s*0x40\s*,/i.test(block.code);
              if (allocatesButNoUpdate) {
                findings.push({
                  title: `Assembly Allocates Memory Without Updating Free Pointer`,
                  severity: 'medium',
                  contract: `${contract.name} (${file.file})`,
                  evidence: { line: block.lineStart },
                  impact: 'Assembly allocates memory but does not update the free memory pointer at 0x40. Subsequent Solidity memory allocations will overlap with the assembly-allocated region, causing data corruption.',
                  remediation: 'After allocating memory in assembly, update the free memory pointer: mstore(0x40, newFreePointer)',
                  poc: { scenario: 'Assembly writes to 0x100, but free pointer still at 0x80 → Solidity allocates at 0x80, overwrites assembly data' },
                });
              }
            }
          }

          // Pattern 3: assembly with sload/sstore — storage collision
          if (/sload|sstore/i.test(block.code)) {
            const usesHardcodedSlot = /sload\s*\(\s*\d+\)|sstore\s*\(\s*\d+,\s*/i.test(block.code);
            if (usesHardcodedSlot) {
              findings.push({
                title: `Assembly Uses Hardcoded Storage Slot — may collide with Solidity layout`,
                severity: 'high',
                contract: `${contract.name} (${file.file})`,
                evidence: {
                  code: block.code.match(/s(?:load|store)\s*\([^)]+\)/g)?.join(', '),
                  line: block.lineStart,
                },
                impact: 'Assembly uses hardcoded storage slot numbers (sload/sstore with numeric slot). These slots may collide with Solidity-declared state variables. Writing to slot N in assembly overwrites the Nth state variable. If slot 0 is the owner, sstore(0, attackerAddress) overwrites the owner → full contract takeover.',
                remediation: 'Use .slot and .offset to reference Solidity variables from assembly: assembly { sload(owner.slot) }. Never hardcode slot numbers.',
                poc: {
                  attackFlow: [
                    '1. Assembly sstore(0, newValue) writes to slot 0',
                    '2. Slot 0 = owner address in Solidity layout',
                    '3. Owner overwritten → attacker becomes owner',
                    '4. Attacker calls withdrawAll() → funds drained',
                  ],
                },
              });
            }
          }

          // Pattern 4: assembly return/stop — may skip Solidity post-checks
          if (/\breturn\b|\bstop\b/i.test(block.code)) {
            findings.push({
              title: `Assembly return/stop — may skip Solidity post-conditions`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { code: block.code.match(/(?:return|stop)\s*\([^)]*\)/g)?.join(', '), line: block.lineStart },
              impact: 'Assembly return/stop immediately ends execution, skipping any Solidity code after the assembly block. If there are post-condition checks, events, or state updates after the assembly block, they are never reached.',
              remediation: 'Avoid return/stop in assembly blocks embedded in Solidity functions. Let Solidity handle the return flow.',
              poc: { scenario: 'Assembly return skips: emit Withdrawal(user, amount); // never reached' },
            });
          }

          // Pattern 5: assembly call/create — gas and value issues
          if (/\bcall\b|\bstaticcall\b|\bcreate\b|\bcreate2\b/i.test(block.code)) {
            // Check for gas specification
            const callMatches = [...block.code.matchAll(/call\s*\(([^)]*)\)/gi)];
            for (const m of callMatches) {
              const args = m[1].split(',').map(a => a.trim());
              // call(gas, addr, value, argsOffset, argsSize, retOffset, retSize)
              // Check if gas is hardcoded to a low value
              if (args[0] && /^\d+$/.test(args[0]) && parseInt(args[0]) < 100000) {
                findings.push({
                  title: `Assembly call with low hardcoded gas — may fail on complex recipients`,
                  severity: 'medium',
                  contract: `${contract.name} (${file.file})`,
                  evidence: { gasValue: args[0], line: block.lineStart },
                  impact: `Assembly call() uses only ${args[0]} gas. If the called contract has complex logic, the call may run out of gas and fail. The return value must be checked to detect this.`,
                  remediation: 'Use gas() to forward available gas, or use a sufficiently high value. Always check the return value of call().',
                  poc: { scenario: `call(50000, ...) → recipient needs 60000 gas → call fails silently` },
                });
              }
            }

            // Check for value in call (ETH transfer via assembly)
            if (/call\s*\([^)]*,\s*[^,]+,\s*[^,]+,/i.test(block.code)) {
              findings.push({
                title: `Assembly call with value — ETH transfer without reentrancy guard`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                evidence: { line: block.lineStart },
                impact: 'Assembly call with non-zero value sends ETH. This bypasses any Solidity-level reentrancy guards that only check for high-level calls. State must be updated BEFORE the assembly call.',
                remediation: 'Update all state before the assembly call. Ensure reentrancy guard covers assembly-level calls too.',
                poc: { scenario: 'Assembly call sends ETH before state update → reentrancy via callback' },
              });
            }
          }

          // Pattern 6: selfdestruct in assembly
          if (/selfdestruct/i.test(block.code)) {
            findings.push({
              title: `selfdestruct in Assembly — contract can be killed`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              evidence: { line: block.lineStart },
              impact: 'Assembly selfdestruct destroys the contract and sends all ETH to the specified address. All user funds are lost. Contract code is permanently removed from state.',
              remediation: 'Remove selfdestruct. If absolutely necessary, add access control and timelock.',
              poc: { attackFlow: ['1. Assembly selfdestruct(addr) called', '2. Contract destroyed', '3. All ETH sent to addr', '4. All user funds permanently lost'] },
            });
          }

          // Pattern 7: delegatecall in assembly
          if (/delegatecall/i.test(block.code)) {
            findings.push({
              title: `delegatecall in Assembly — storage collision risk`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { line: block.lineStart },
              impact: 'Assembly delegatecall executes code in the context of the calling contract\'s storage. If the target address is controllable, attacker can overwrite any storage slot including owner. Even with fixed targets, storage layout must match perfectly.',
              remediation: 'Ensure delegatecall target is fixed and trusted. Verify storage layout compatibility. Use EIP-1967 slots for proxy-specific variables.',
              poc: { attackFlow: ['1. Assembly delegatecall with controllable target', '2. Attacker sets target to malicious contract', '3. Malicious code writes to slot 0 (owner)', '4. Attacker becomes owner → full takeover'] },
            });
          }
        }
      }
    }
    return findings;
  },

  _findAssemblyBlocks(source) {
    const blocks = [];
    const re = /assembly\s*(?:\([^)]*\))?\s*\{/g;
    let m;
    while ((m = re.exec(source)) !== null) {
      const start = source.indexOf('{', m.index) + 1;
      let depth = 1;
      for (let i = start; i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}') { depth--; if (depth === 0) {
          blocks.push({
            code: source.substring(start, i),
            lineStart: source.substring(0, m.index).split('\n').length,
          });
          break;
        }}
      }
    }
    return blocks;
  },
};
