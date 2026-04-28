const fs = require('fs');
const path = require('path');
const glob = require('glob');

class Parser {
  constructor() {
    this.patterns = {
      pragma: /pragma\s+solidity\s+([^;]+);/g,
      contractDecl: /\b(contract|library|interface|abstract\s+contract)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{/g,
      functionDecl: /function\s+(\w+)\s*\(([^)]*)\)\s*([\s\S]*?)\s*\{/g,
      stateVar: /\b(uint\d*|int\d*|address|bool|string|bytes\d*|mapping|IERC20|SafeERC20)\s+(?:\[(?:\d*)\]\s*)?(\w+)(?:\s*=|;)/g,
      eventDecl: /event\s+(\w+)\s*\(([^)]*)\)/g,
      modifierDecl: /modifier\s+(\w+)\s*\(([^)]*)\)\s*\{/g,
      externalCall: /(\w+)\.(?:transfer|send|call|delegatecall|staticcall)\s*\(/g,
      payableFunc: /payable\s*\(/g,
      requireStmt: /require\s*\(([^)]+)\)/g,
      emitStmt: /emit\s+(\w+)\s*\(/g,
      importStmt: /import\s+[^;]+;/g,
      inheritance: /\bcontract\s+\w+\s+is\s+([^{]+)/g,
    };
  }

  parseFile(filePath) {
    const source = fs.readFileSync(filePath, 'utf8');
    return this.parse(source, filePath);
  }

  parse(source, filePath) {
    const result = {
      file: filePath,
      pragma: this._extract(source, this.patterns.pragma, 1),
      contracts: [],
      imports: this._extractAll(source, this.patterns.importStmt, 0),
    };

    // Extract contracts
    let contractMatch;
    const contractRe = new RegExp(this.patterns.contractDecl.source, 'g');
    while ((contractMatch = contractRe.exec(source)) !== null) {
      const contractType = contractMatch[1];
      const contractName = contractMatch[2];
      const inheritance = contractMatch[3]?.split(',').map(s => s.trim()) || [];
      
      // Find contract body
      const bodyStart = source.indexOf('{', contractMatch.index) + 1;
      const body = this._extractBlock(source, bodyStart - 1);

      result.contracts.push({
        name: contractName,
        type: contractType,
        inheritance,
        stateVariables: this._extractStateVars(body),
        functions: this._extractFunctions(body, contractName),
        events: this._extractEvents(body),
        modifiers: this._extractModifiers(body),
        externalCalls: this._extractExternalCalls(body),
        hasFallback: /fallback\s*\(/g.test(body),
        hasReceive: /receive\s*\(\s*\)\s*(?:external\s+)?payable/g.test(body),
        lineStart: this._getLineNumber(source, contractMatch.index),
      });
    }

    return result;
  }

  parseProject(dirPath, exclude) {
    const excludeList = (exclude || '').split(',').filter(Boolean);
    const solFiles = glob.sync('**/*.sol', { cwd: dirPath, ignore: excludeList });
    const results = [];
    for (const file of solFiles) {
      try {
        results.push(this.parseFile(path.join(dirPath, file)));
      } catch (err) {
        results.push({ file, error: err.message });
      }
    }
    return results;
  }

  _extract(source, regex, group) {
    const match = new RegExp(regex.source).exec(source);
    return match ? match[group] : null;
  }

  _extractAll(source, regex, group) {
    const results = [];
    let match;
    const re = new RegExp(regex.source, 'g');
    while ((match = re.exec(source)) !== null) results.push(match[group]);
    return results;
  }

  _extractBlock(source, openBraceIdx) {
    let depth = 0;
    let start = -1;
    for (let i = openBraceIdx; i < source.length; i++) {
      if (source[i] === '{') {
        if (depth === 0) start = i + 1;
        depth++;
      } else if (source[i] === '}') {
        depth--;
        if (depth === 0) return source.substring(start, i);
      }
    }
    return source.substring(start || openBraceIdx);
  }

  _extractStateVars(body) {
    const vars = [];
    const re = /\b(uint\d*|int\d*|address|bool|string|bytes\d*|mapping\s*<[^>]+>|IERC20|SafeERC20|I[\w]+)\s+(?:\[(?:\d*)\]\s*)?(public|private|internal|external)?\s*(?:constant\s+)?(?:override\s+)?(\w+)(?:\s*=([^;]+))?;/g;
    let m;
    while ((m = re.exec(body)) !== null) {
      vars.push({ type: m[1].trim(), visibility: m[2] || 'default', name: m[3], initialValue: m[4]?.trim() });
    }
    return vars;
  }

  _extractFunctions(body, contractName) {
    const fns = [];
    const re = /function\s+(\w+)\s*\(([^)]*)\)\s*([\s\S]*?)\{/g;
    let m;
    while ((m = re.exec(body)) !== null) {
      const attrs = m[3];
      fns.push({
        name: m[1],
        params: m[2].trim(),
        visibility: /public/.test(attrs) ? 'public' : /external/.test(attrs) ? 'external' : /internal/.test(attrs) ? 'internal' : /private/.test(attrs) ? 'private' : 'default',
        mutability: /view/.test(attrs) ? 'view' : /pure/.test(attrs) ? 'pure' : /payable/.test(attrs) ? 'payable' : 'nonpayable',
        isVirtual: /virtual/.test(attrs),
        isOverride: /override/.test(attrs),
        modifiers: [...attrs.matchAll(/(\w+)\(/g)].map(x => x[1]).filter(n => !['require','emit','assert','revert','abi','block','msg','tx'].includes(n)),
        hasExternalCall: /(\w+)\.(?:transfer|send|call|delegatecall|staticcall)\s*\(/.test(attrs + body.substring(body.indexOf(m[0]), body.indexOf(m[0]) + 500)),
      });
    }
    return fns;
  }

  _extractEvents(body) {
    const events = [];
    const re = /event\s+(\w+)\s*\(([^)]*)\)/g;
    let m;
    while ((m = re.exec(body)) !== null) events.push({ name: m[1], params: m[2].trim() });
    return events;
  }

  _extractModifiers(body) {
    const mods = [];
    const re = /modifier\s+(\w+)\s*\(([^)]*)\)/g;
    let m;
    while ((m = re.exec(body)) !== null) mods.push({ name: m[1], params: m[2].trim() });
    return mods;
  }

  _extractExternalCalls(body) {
    const calls = [];
    const re = /(\w+)\.(transfer|send|call|delegatecall|staticcall)\s*\(/g;
    let m;
    while ((m = re.exec(body)) !== null) calls.push({ target: m[1], method: m[2] });
    return calls;
  }

  _getLineNumber(source, index) {
    return source.substring(0, index).split('\n').length;
  }
}

module.exports = Parser;
