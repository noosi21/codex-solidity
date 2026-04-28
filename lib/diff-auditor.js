/**
 * Diff Auditing Module
 * Integrates with git to only audit changed functions between commits/branches.
 * Dramatically speeds up re-audits on large codebases.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class DiffAuditor {
  constructor(opts = {}) {
    this.repoRoot = opts.repoRoot || this._findRepoRoot();
    this.parser = opts.parser || null;
  }

  _findRepoRoot() {
    try {
      return execSync('git rev-parse --show-toplevel', { encoding: 'utf8' }).trim();
    } catch { return process.cwd(); }
  }

  getChangedFiles(baseRef, headRef) {
    try {
      const cmd = headRef
        ? `git diff --name-only --diff-filter=ACMR "${baseRef}"..."${headRef}"`
        : `git diff --name-only --diff-filter=ACMR "${baseRef}"`;
      const output = execSync(cmd, { encoding: 'utf8', cwd: this.repoRoot });
      return output.trim().split('\n').filter(f => f.endsWith('.sol'));
    } catch {
      // Fallback: diff against HEAD
      try {
        const output = execSync('git diff --name-only --diff-filter=ACMR HEAD', { encoding: 'utf8', cwd: this.repoRoot });
        return output.trim().split('\n').filter(f => f.endsWith('.sol'));
      } catch { return []; }
    }
  }

  getChangedFunctions(baseRef, headRef) {
    const changedFiles = this.getChangedFiles(baseRef, headRef);
    const changedFunctions = [];

    for (const file of changedFiles) {
      const filePath = path.join(this.repoRoot, file);
      if (!fs.existsSync(filePath)) continue;

      try {
        const diffCmd = headRef
          ? `git diff "${baseRef}"..."${headRef}" -- "${file}"`
          : `git diff "${baseRef}" -- "${file}"`;
        const diff = execSync(diffCmd, { encoding: 'utf8', cwd: this.repoRoot });

        const changedLines = this._parseDiffHunks(diff);
        const source = fs.readFileSync(filePath, 'utf8');

        // Find which functions contain the changed lines
        const functions = this._mapLinesToFunctions(source, changedLines);
        for (const fn of functions) {
          changedFunctions.push({
            file,
            function: fn.name,
            lineStart: fn.lineStart,
            lineEnd: fn.lineEnd,
            visibility: fn.visibility,
            mutability: fn.mutability,
            changeType: fn.changeType,
          });
        }
      } catch { /* skip unreadable files */ }
    }

    return changedFunctions;
  }

  _parseDiffHunks(diff) {
    const lines = new Set();
    const hunks = diff.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/g);
    if (!hunks) return lines;

    for (const hunk of hunks) {
      const match = hunk.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
      if (match) {
        const startLine = parseInt(match[1]);
        const count = parseInt(match[2] || '1');
        for (let i = startLine; i < startLine + count; i++) {
          lines.add(i);
        }
      }
    }
    return lines;
  }

  _mapLinesToFunctions(source, changedLines) {
    const functions = [];
    const lines = source.split('\n');

    // Track function boundaries
    const fnPattern = /function\s+(\w+)\s*\([^)]*\)\s*([\s\S]*?)\{/g;
    let match;
    let sourceIdx = 0;

    while ((match = fnPattern.exec(source)) !== null) {
      const lineStart = source.substring(0, match.index).split('\n').length;
      const attrs = match[2] || '';

      // Find closing brace for this function
      const bodyStart = source.indexOf('{', match.index) + 1;
      let depth = 1;
      let bodyEnd = bodyStart;
      for (let i = bodyStart; i < source.length && depth > 0; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}') depth--;
        if (depth === 0) { bodyEnd = i; break; }
      }

      const lineEnd = source.substring(0, bodyEnd).split('\n').length;

      // Check if any changed lines fall within this function
      let hasChanges = false;
      for (let l = lineStart; l <= lineEnd; l++) {
        if (changedLines.has(l)) { hasChanges = true; break; }
      }

      if (hasChanges) {
        functions.push({
          name: match[1],
          lineStart,
          lineEnd,
          visibility: /public/.test(attrs) ? 'public' : /external/.test(attrs) ? 'external' : /internal/.test(attrs) ? 'internal' : /private/.test(attrs) ? 'private' : 'default',
          mutability: /view/.test(attrs) ? 'view' : /pure/.test(attrs) ? 'pure' : /payable/.test(attrs) ? 'payable' : 'nonpayable',
          changeType: 'modified',
        });
      }
    }

    // Also check for state variable changes (lines outside functions)
    const stateVarPattern = /\b(uint\d*|int\d*|address|bool|string|bytes\d*|mapping)\s+(?:\[(?:\d*)\]\s*)?(public|private|internal)?\s*(?:constant\s+)?(\w+)\s*[;=]/g;
    while ((match = stateVarPattern.exec(source)) !== null) {
      const line = source.substring(0, match.index).split('\n').length;
      if (changedLines.has(line)) {
        functions.push({
          name: `stateVar:${match[3]}`,
          lineStart: line,
          lineEnd: line,
          visibility: match[2] || 'default',
          mutability: 'state',
          changeType: 'state-variable-modified',
        });
      }
    }

    return functions;
  }

  filterContractsToAudit(parsedResults, changedFunctions) {
    if (!changedFunctions || changedFunctions.length === 0) return parsedResults;

    const changedMap = {};
    for (const cf of changedFunctions) {
      if (!changedMap[cf.file]) changedMap[cf.file] = new Set();
      changedMap[cf.file].add(cf.function);
    }

    return parsedResults.map(result => {
      if (result.error) return result;
      const changedFns = changedMap[result.file];
      if (!changedFns) return null; // File not changed, skip entirely

      // Filter to only changed functions
      const filteredContracts = result.contracts.map(contract => ({
        ...contract,
        functions: contract.functions.filter(fn => {
          if (changedFns.has(fn.name)) return true;
          // Always include constructor, fallback, receive if file changed
          if (['constructor', 'fallback', 'receive'].includes(fn.name) && changedFns.size > 0) return true;
          return false;
        }),
      })).filter(c => c.functions.length > 0 || c.stateVariables.some(v => changedFns.has(`stateVar:${v.name}`)));

      if (filteredContracts.length === 0) return null;
      return { ...result, contracts: filteredContracts, diffFiltered: true };
    }).filter(Boolean);
  }

  getDiffSummary(baseRef, headRef) {
    const files = this.getChangedFiles(baseRef, headRef);
    const functions = this.getChangedFunctions(baseRef, headRef);
    const stateVarChanges = functions.filter(f => f.changeType === 'state-variable-modified');
    const fnChanges = functions.filter(f => f.changeType === 'modified');

    return {
      baseRef,
      headRef: headRef || 'working-tree',
      changedFiles: files.length,
      solFiles: files,
      changedFunctions: fnChanges.length,
      changedStateVars: stateVarChanges.length,
      highRiskChanges: fnChanges.filter(f =>
        f.visibility === 'external' || f.visibility === 'public' ||
        f.mutability === 'payable' || f.mutability === 'nonpayable'
      ).length,
      summary: `${files.length} Solidity files changed, ${fnChanges.length} functions modified, ${stateVarChanges.length} state vars changed, ${fnChanges.filter(f => f.visibility === 'external' || f.visibility === 'public').length} public/external functions affected`,
    };
  }
}

module.exports = DiffAuditor;
