module.exports = {
  name: 'storage-pointer',
  aliases: ['uninitialized-storage', 'storage-pointer-bug'],
  severity: 'high',
  description: 'Uninitialized Storage Pointer — local storage variable points to slot 0, overwrites critical state',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');
      const pragma = file.pragma || '';

      for (const contract of file.contracts || []) {
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          // Pattern 1: Struct/Array declared as storage without assignment (Solidity <0.5.0)
          const uninitStorage = this._findUninitializedStorage(fnBody, fn.name);
          for (const vuln of uninitStorage) {
            findings.push({
              title: `Uninitialized Storage Pointer — ${fn.name}() ${vuln.type} ${vuln.varName} points to slot 0`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: {
                type: vuln.type,
                varName: vuln.varName,
                code: vuln.code,
                pragma: pragma || 'not specified',
              },
              impact: `Local ${vuln.type} variable "${vuln.varName}" is declared as storage but not assigned. In Solidity <0.5.0, uninitialized storage pointers default to slot 0. Writing to this variable OVERWRITES the first storage slot — which is typically the owner address or a critical balance mapping. This can:
1. Overwrite owner → attacker becomes owner → drain all funds
2. Overwrite balances mapping → attacker gets infinite balance
3. Overwrite totalSupply → accounting completely broken`,
              remediation: 'Always initialize storage variables: MyStruct storage s = myMapping[key]; Or use memory if data should not persist. Upgrade to Solidity >=0.5.0 where this is a compiler error.',
              poc: {
                attackFlow: [
                  `1. ${fn.name}() declares: ${vuln.code}`,
                  '2. Uninitialized storage pointer defaults to slot 0',
                  '3. Slot 0 typically holds: owner address or first state variable',
                  '4. Writing to varName overwrites slot 0',
                  '5. If slot 0 = owner → attacker becomes owner',
                  '6. Attacker calls withdrawAll() as new owner → funds drained',
                ],
                storageImpact: {
                  slot0: 'OVERWRITTEN — typically owner address or critical variable',
                  result: 'Access control bypassed or accounting destroyed',
                },
              },
            });
          }

          // Pattern 2: Struct in memory that should be storage (data not saved)
          const memoryNotSaved = this._findMemoryNotSaved(fnBody, fn.name, source);
          for (const vuln of memoryNotSaved) {
            findings.push({
              title: `Struct in Memory — ${fn.name}() modifies memory copy, changes not persisted`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { code: vuln.code, varName: vuln.varName },
              impact: `Struct "${vuln.varName}" is loaded into memory, modified, but never written back to storage. All modifications are lost when the function returns. If this struct tracks balances or approvals, the "updates" don't actually happen — accounting is broken.`,
              remediation: 'Use storage pointer: MyStruct storage s = structs[key]; Modifications to s persist. Or explicitly save back to storage after memory modifications.',
              poc: { scenario: 'Struct loaded in memory, balance updated in memory, function returns → balance NOT updated in storage' },
            });
          }
        }

        // Pattern 3: Mapping in memory (impossible — but check for anti-patterns)
        if (contract.stateVariables) {
          for (const sv of contract.stateVariables) {
            if (sv.type?.includes('mapping') && sv.visibility === 'public') {
              // Check if mapping is iterated (not possible in Solidity)
              const sourceAfterVar = source.substring(source.indexOf(sv.name));
              if (/for.*mapping|forEach|iterate/i.test(sourceAfterVar.substring(0, 500))) {
                findings.push({
                  title: `Mapping Iteration Attempt — cannot iterate mapping ${sv.name}`,
                  severity: 'low',
                  contract: `${contract.name} (${file.file})`,
                  evidence: { variable: sv.name, type: sv.type },
                  impact: 'Mappings cannot be iterated in Solidity. Any logic that attempts to iterate a mapping will not work as intended.',
                  remediation: 'Maintain a separate array of keys alongside the mapping for iteration.',
                  poc: { note: 'Design issue, not directly exploitable' },
                });
              }
            }
          }
        }
      }
    }
    return findings;
  },

  _findUninitializedStorage(body, fnName) {
    const vulns = [];
    // Struct declaration without assignment
    const structRe = /(\w+)\s+storage\s+(\w+)\s*;/g;
    let m;
    while ((m = structRe.exec(body)) !== null) {
      // Check if it's assigned later
      const afterDecl = body.substring(m.index + m[0].length);
      const hasAssignment = new RegExp(`${m[2]}\\s*=`).test(afterDecl.substring(0, 200));
      if (!hasAssignment) {
        vulns.push({ type: 'struct', varName: m[2], code: m[0] });
      }
    }

    // Array declaration without assignment
    const arrayRe = /(\w+)\[\]\s+storage\s+(\w+)\s*;/g;
    while ((m = arrayRe.exec(body)) !== null) {
      const afterDecl = body.substring(m.index + m[0].length);
      const hasAssignment = new RegExp(`${m[2]}\\s*=`).test(afterDecl.substring(0, 200));
      if (!hasAssignment) {
        vulns.push({ type: 'array', varName: m[2], code: m[0] });
      }
    }

    return vulns;
  },

  _findMemoryNotSaved(body, fnName, source) {
    const vulns = [];
    // Struct loaded as memory, modified, but not saved back
    const memStructRe = /(\w+)\s+memory\s+(\w+)\s*=\s*[^;]+;/g;
    let m;
    while ((m = memStructRe.exec(body)) !== null) {
      const varName = m[2];
      // Check if variable is modified
      const isModified = new RegExp(`${varName}\\.[\\w]+\\s*=`).test(body);
      // Check if it's saved back to storage
      const isSavedBack = new RegExp(`\\w+\\[.*\\]\\s*=\\s*${varName}|\\w+\\.push\\s*\\(\\s*${varName}`).test(body);

      if (isModified && !isSavedBack) {
        vulns.push({ varName, code: m[0] });
      }
    }
    return vulns;
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
