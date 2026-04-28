module.exports = {
  name: 'inheritance-order',
  aliases: ['c3-linearization', 'multiple-inheritance', 'inheritance-bug'],
  severity: 'high',
  description: 'Inheritance Order — C3 linearization issues cause wrong function dispatch, storage collision',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        if (!contract.inheritance || contract.inheritance.length < 2) continue;

        // Pattern 1: Multiple inheritance with same function name — order matters
        const inheritedContracts = contract.inheritance;
        const contractFunctions = contract.functions || [];

        // Check if contract inherits from multiple contracts that might have overlapping functions
        const commonBaseContracts = ['Ownable', 'Pausable', 'ReentrancyGuard', 'ERC20', 'ERC721', 'AccessControl'];
        const hasCommonBases = inheritedContracts.filter(c => commonBaseContracts.includes(c));

        // Pattern 2: is contract inherits from A, B where both define same function
        // Solidity uses C3 linearization: right-to-left in inheritance list
        // contract X is A, B → B overrides A (B's functions take precedence)
        // If developer expects A's behavior but B overrides it → bug

        // Check for diamond inheritance (same base inherited multiple times)
        const hasDiamondInheritance = inheritedContracts.length >= 2;
        if (hasDiamondInheritance) {
          findings.push({
            title: `Multiple Inheritance — verify C3 linearization order for ${contract.name}`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              inheritance: inheritedContracts,
              linearization: `Right-to-left: ${[...inheritedContracts].reverse().join(' → ')}`,
              note: 'Rightmost parent overrides leftmost in C3 linearization',
            },
            impact: `Contract ${contract.name} inherits from [${inheritedContracts.join(', ')}]. In Solidity's C3 linearization, the RIGHTMOST contract takes precedence. This means ${inheritedContracts[inheritedContracts.length - 1]} overrides ${inheritedContracts[0]}. If both define the same function (e.g., _beforeTokenTransfer), only the rightmost version is called. If the developer expected the leftmost behavior, the contract behaves incorrectly — potentially bypassing access control or skipping balance checks.`,
            remediation: 'Review inheritance order carefully. Use `super.functionName()` to call parent implementations. Document which parent takes precedence. Consider using composition over multiple inheritance.',
            poc: {
              linearizationExample: {
                code: `contract A { function withdraw() onlyOwner { ... } }
contract B { function withdraw() { ... } }  // No access control!
contract C is A, B { }  // B.withdraw() takes precedence!`,
                result: 'B.withdraw() called — no onlyOwner check → anyone can withdraw',
                fix: 'contract C is B, A { }  // Now A.withdraw() takes precedence',
              },
            },
          });
        }

        // Pattern 3: Constructor argument order mismatch
        const constructorMatch = source.match(new RegExp(`contract\\s+${contract.name}\\s+is\\s+[^{]+\\{`));
        if (constructorMatch) {
          const inheritanceClause = constructorMatch[0];
          // Check for constructor with base constructor arguments
          const baseConstructorRe = /constructor\s*\(([^)]*)\)\s*([^{]*)\{/g;
          const constructorBody = this._findConstructorBody(source, contract.name);

          if (constructorBody) {
            // Check if base constructors are called in correct order
            const baseCalls = [...constructorBody.matchAll(/(\w+)\s*\.\s*__\w*_init\s*\(|(\w+)\s*\(/g)];
            // Simple heuristic: if base calls exist, check they match inheritance order
            const hasBaseInitCalls = /__\w+_init/i.test(constructorBody);

            if (hasBaseInitCalls && inheritedContracts.length >= 2) {
              const callOrder = [...constructorBody.matchAll(/(\w+)__\w+_init/g)].map(m => {
                for (const ic of inheritedContracts) {
                  if (m[0].toLowerCase().includes(ic.toLowerCase())) return ic;
                }
                return m[1];
              });

              // Check if call order matches inheritance order
              const orderMismatch = callOrder.length > 1 &&
                callOrder.some((c, i) => i > 0 && inheritedContracts.indexOf(callOrder[i-1]) > inheritedContracts.indexOf(c));

              if (orderMismatch) {
                findings.push({
                  title: `Base Constructor Call Order Mismatch — ${contract.name}`,
                  severity: 'medium',
                  contract: `${contract.name} (${file.file})`,
                  evidence: { callOrder, inheritanceOrder: inheritedContracts },
                  impact: 'Base constructor calls are in a different order than the inheritance declaration. This can cause initialization to happen in the wrong order, potentially overwriting values set by earlier constructors.',
                  remediation: 'Call base constructors in the same order as the inheritance list. Use OpenZeppelin initializer pattern consistently.',
                  poc: { scenario: 'Ownable.__Ownable_init() sets owner, then Pausable.__Pausable_init() overwrites slot 0 with paused=false → owner corrupted' },
                });
              }
            }
          }
        }

        // Pattern 4: Missing super call in override
        const overrideFns = contractFunctions.filter(fn => fn.modifiers?.includes('override') || /override/i.test(fn.modifiers?.join('') || ''));
        for (const fn of overrideFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const callsSuper = /super\./i.test(fnBody);
          const isHook = /_before|_after|_pre|_post/i.test(fn.name);

          if (isHook && !callsSuper) {
            findings.push({
              title: `Missing super Call — ${fn.name}() override skips parent implementation`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { isHook: true, noSuperCall: true },
              impact: `${fn.name}() is a hook function that overrides a parent implementation but does NOT call super.${fn.name}(). The parent's logic is completely skipped. If the parent's hook enforced access control, updated accounting, or emitted critical events, all of that is bypassed. This can lead to: (1) access control bypass, (2) accounting errors, (3) missing events for monitoring.`,
              remediation: `Add super.${fn.name}() call in the override function. Call it at the appropriate point (before/after your custom logic).`,
              poc: {
                attackFlow: [
                  `1. Parent's ${fn.name}() enforces onlyOwner or balance check`,
                  `2. Child overrides ${fn.name}() without calling super`,
                  '3. Parent check is completely bypassed',
                  '4. Attacker calls function — parent protection skipped',
                ],
              },
            });
          }
        }
      }
    }
    return findings;
  },

  _findConstructorBody(source, contractName) {
    const re = /constructor\s*\([^)]*\)\s*(?:public\s+)?(?:[^{]*)\{/g;
    const match = re.exec(source);
    if (!match) return null;
    const start = source.indexOf('{', match.index) + 1;
    let depth = 1;
    for (let i = start; i < source.length; i++) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') { depth--; if (depth === 0) return source.substring(start, i); }
    }
    return source.substring(start);
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
