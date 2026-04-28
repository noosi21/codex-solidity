module.exports = {
  name: 'shadowing',
  aliases: ['state-variable-shadowing', 'variable-shadowing'],
  severity: 'high',
  description: 'State Variable Shadowing — child contract redeclares parent variable, storage collision causes fund loss',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        if (!contract.inheritance || contract.inheritance.length === 0) continue;

        // Pattern 1: Child redeclares state variables that exist in parent
        const childVars = contract.stateVariables || [];
        
        // Check for common shadowed variables
        const shadowProne = ['owner', 'balances', 'balanceOf', 'paused', 'totalSupply', 'decimals', 'name', 'symbol', 'implementation', 'admin'];
        const potentiallyShadowed = childVars.filter(v => shadowProne.includes(v.name));

        if (potentiallyShadowed.length > 0) {
          findings.push({
            title: `State Variable Shadowing — ${potentiallyShadowed.map(v => v.name).join(', ')} redeclared in child`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              shadowedVars: potentiallyShadowed.map(v => ({ name: v.name, type: v.type, visibility: v.visibility })),
              inheritance: contract.inheritance,
              risk: 'Child variable occupies different storage slot than parent — writes to child var do NOT update parent var',
            },
            impact: `Child contract ${contract.name} redeclares state variable(s) from parent: ${potentiallyShadowed.map(v => v.name).join(', ')}. In Solidity, the child's variable occupies a NEW storage slot, NOT the parent's slot. This means:
- Writing to child's "owner" does NOT update parent's "owner" → access control broken
- Writing to child's "balances" does NOT update parent's "balances" → accounting broken
- Reading from child's variable reads the CHILD slot (default 0), not parent's actual value
An attacker can exploit this by: (1) calling parent functions that read parent's "owner" (which attacker can set via parent function), (2) calling child functions that read child's "owner" (which is different), creating authorization bypass and fund drain scenarios.`,
            remediation: 'Remove duplicate state variable declarations in child contracts. Use parent variables directly via inheritance. If overriding is needed, use the `override` keyword with functions, not variable redeclaration.',
            poc: {
              attackFlow: [
                `1. Parent has: address public owner (slot 0)`,
                `2. Child redeclares: address public owner (slot N, different!)`,
                `3. Parent's onlyOwner checks parent.owner (slot 0)`,
                `4. Child writes to child.owner (slot N) — parent.owner stays 0x0`,
                `5. If parent.owner is 0x0, anyone can call onlyOwner functions (address(0) check bypass)`,
                `6. Attacker calls withdrawAll() — funds drained`,
              ],
              storageLayout: {
                parentSlot0: 'owner = 0x0 (never set by child)',
                childSlotN: 'owner = msg.sender (set by child constructor)',
                result: 'Parent functions read 0x0 as owner — authorization bypassed',
              },
            },
          });
        }

        // Pattern 2: Local variable shadows state variable
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const stateVarNames = childVars.map(v => v.name);
          // Find local declarations that shadow state vars
          const localDeclRe = /\b(?:uint\d*|int\d*|address|bool|string|bytes\d*)\s+(?:payable\s+)?(\w+)\s*[=;]/g;
          let m;
          while ((m = localDeclRe.exec(fnBody)) !== null) {
            const localName = m[1];
            if (stateVarNames.includes(localName)) {
              findings.push({
                title: `Local Variable Shadows State Variable — ${localName} in ${fn.name}()`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                function: fn.name,
                evidence: {
                  localVar: localName,
                  declaration: m[0],
                  stateVar: localName,
                },
                impact: `Local variable "${localName}" shadows the state variable with the same name. Inside ${fn.name}(), references to "${localName}" refer to the LOCAL variable, not the state variable. This can cause: (1) state variable not updated when intended, (2) balance/accounting errors, (3) access control checks use wrong value.`,
                remediation: `Rename the local variable to avoid shadowing. Use this.${localName} to explicitly reference the state variable. Use a linter that detects shadowing.`,
                poc: { scenario: `uint balance = 0; // shadows state var "balance"\n// Later: balance += amount; // updates LOCAL, not STATE\n// State variable unchanged — accounting broken` },
              });
            }
          }
        }

        // Pattern 3: Function parameter shadows state variable
        for (const fn of contract.functions || []) {
          if (!fn.params) continue;
          const stateVarNames = childVars.map(v => v.name);
          const paramNames = fn.params.split(',').map(p => p.trim().split(/\s+/).pop());
          const shadowedParams = paramNames.filter(p => stateVarNames.includes(p));

          if (shadowedParams.length > 0) {
            findings.push({
              title: `Function Parameter Shadows State Variable — ${shadowedParams.join(', ')} in ${fn.name}()`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { shadowedParams, stateVars: shadowedParams },
              impact: `Function parameter(s) ${shadowedParams.join(', ')} shadow state variable(s). Inside ${fn.name}(), using "${shadowedParams[0]}" refers to the parameter, not the state variable. If the function intended to update the state variable, it updates the parameter instead — state unchanged.`,
              remediation: 'Rename function parameters to avoid shadowing state variables. Use underscore prefix for parameters (e.g., _owner instead of owner).',
              poc: { scenario: `function setOwner(address owner) { owner = owner; // Sets PARAMETER to itself, state var unchanged }` },
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
