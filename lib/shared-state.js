/**
 * Shared State Analysis
 * Skills share context during execution, enabling real-time cross-skill awareness.
 * Instead of post-hoc correlation, skills can read findings from other skills as they run.
 */

class SharedState {
  constructor() {
    this.findings = [];
    this.taintMap = {};       // variable -> taint source
    this.callGraph = {};      // contract -> called contracts
    this.stateWrites = {};    // function -> [state vars written]
    this.externalCalls = {};  // function -> [external call targets]
    this.accessPaths = {};   // function -> [access control requirements]
    this.contractContext = {}; // contract -> metadata (isVault, isProxy, isToken, etc.)
    this.knownPatterns = {};  // pattern -> [findings that match]
  }

  addFinding(finding) {
    this.findings.push(finding);
    this._updateMaps(finding);
  }

  addFindings(findings) {
    for (const f of findings) this.addFinding(f);
  }

  getFindingsForSkill(skillName) {
    return this.findings.filter(f => f.skill === skillName);
  }

  getFindingsForContract(contractName) {
    return this.findings.filter(f => f.contract === contractName);
  }

  getFindingsForFunction(functionName) {
    return this.findings.filter(f => f.functionName === functionName);
  }

  getContextForSkill(skillName) {
    const ctx = {
      relatedFindings: [],
      taintSources: {},
      stateWriteConflicts: [],
      callChainRisks: [],
      accessControlGaps: [],
      contractTypes: {},
    };

    // Findings from other skills that relate to this skill's domain
    const skillRelations = this._getSkillRelations(skillName);
    for (const relatedSkill of skillRelations) {
      ctx.relatedFindings.push(...this.getFindingsForSkill(relatedSkill));
    }

    // Taint sources relevant to this skill
    ctx.taintSources = { ...this.taintMap };

    // State write conflicts: multiple functions writing same variable
    ctx.stateWriteConflicts = this._findStateWriteConflicts();

    // Call chain risks: reentrancy paths through call graph
    ctx.callChainRisks = this._findCallChainRisks(skillName);

    // Access control gaps
    ctx.accessControlGaps = this._findAccessGaps();

    // Contract type context
    ctx.contractTypes = { ...this.contractContext };

    return ctx;
  }

  registerContract(contract) {
    const name = contract.name;
    this.contractContext[name] = {
      isVault: this._isVault(contract),
      isProxy: this._isProxy(contract),
      isToken: this._isToken(contract),
      isLending: /lend|borrow|collateral/i.test(name),
      isBridge: /bridge|cross/i.test(name),
      isAMM: /amm|swap|pool|pair/i.test(name),
      isStaking: /stake|farm|reward/i.test(name),
      hasReentrancyGuard: (contract.modifiers || []).some(m => /nonReentrant|lock/i.test(m.name)),
      hasFallback: contract.hasFallback,
      hasReceive: contract.hasReceive,
      externalCallCount: (contract.externalCalls || []).length,
      stateVarCount: (contract.stateVariables || []).length,
    };

    // Build state write map
    for (const fn of contract.functions || []) {
      if (!fn.body) continue;
      const key = `${name}.${fn.name}`;
      this.stateWrites[key] = [];
      this.externalCalls[key] = [];

      // Find state variable writes
      const writes = [...fn.body.matchAll(/(\w+)\s*(=|\+=|-=|\*=|\/=)\s/g)];
      for (const w of writes) {
        const sv = (contract.stateVariables || []).find(v => v.name === w[1]);
        if (sv) this.stateWrites[key].push({ var: w[1], op: w[2], type: sv.type });
      }

      // Find external calls
      const calls = [...fn.body.matchAll(/(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*\(/g)];
      for (const c of calls) {
        this.externalCalls[key].push({ target: c[1], method: c[2] });
      }
    }

    // Build call graph from inheritance
    for (const parent of contract.inheritance || []) {
      if (!this.callGraph[name]) this.callGraph[name] = [];
      this.callGraph[name].push(parent);
    }
  }

  registerContracts(contracts) {
    for (const c of contracts) this.registerContract(c);
  }

  _updateMaps(finding) {
    // Update taint map
    if (finding.evidence && finding.evidence.includes('taint')) {
      const match = finding.evidence.match(/(\w+)\s*->\s*(\w+)/);
      if (match) this.taintMap[match[2]] = match[1];
    }

    // Update known patterns
    const pattern = finding.skill || 'unknown';
    if (!this.knownPatterns[pattern]) this.knownPatterns[pattern] = [];
    this.knownPatterns[pattern].push(finding);
  }

  _getSkillRelations(skillName) {
    const relations = {
      'reentrancy': ['read-only-reentrancy', 'nft-reentrancy', 'erc4626-vault', 'bridge-vulnerability'],
      'read-only-reentrancy': ['reentrancy', 'oracle-manipulation', 'erc4626-vault'],
      'oracle-manipulation': ['read-only-reentrancy', 'flash-loan', 'liquidation-attack', 'l2-sequencer'],
      'flash-loan': ['oracle-manipulation', 'amm-math', 'front-running'],
      'access-control': ['proxy-upgrade', 'delegatecall', 'self-destruct'],
      'erc4626-vault': ['reentrancy', 'donation-attack', 'rounding-errors', 'read-only-reentrancy'],
      'proxy-upgrade': ['delegatecall', 'access-control', 'storage-pointer'],
      'delegatecall': ['proxy-upgrade', 'access-control', 'storage-pointer'],
      'overflow': ['rounding-errors', 'erc4626-vault'],
      'bridge-vulnerability': ['reentrancy', 'access-control'],
      'liquidation-attack': ['oracle-manipulation', 'flash-loan'],
      'amm-math': ['flash-loan', 'oracle-manipulation', 'front-running'],
      'gas-griefing': ['pool-freeze'],
      'pool-freeze': ['gas-griefing'],
      'unchecked-returns': ['reentrancy'],
      'nft-reentrancy': ['reentrancy', 'erc4626-vault'],
      'donation-attack': ['erc4626-vault', 'rounding-errors'],
      'rounding-errors': ['erc4626-vault', 'overflow'],
      'reward-manipulation': ['flash-loan', 'front-running'],
      'signature-malleability': ['access-control', 'eip-2612-permit'],
      'eip-2612-permit': ['signature-malleability'],
      'storage-pointer': ['delegatecall', 'proxy-upgrade'],
      'l2-sequencer': ['oracle-manipulation', 'liquidation-attack'],
    };
    return relations[skillName] || [];
  }

  _findStateWriteConflicts() {
    const conflicts = [];
    const varWriters = {};

    for (const [fnKey, writes] of Object.entries(this.stateWrites)) {
      for (const w of writes) {
        if (!varWriters[w.var]) varWriters[w.var] = [];
        varWriters[w.var].push({ function: fnKey, op: w.op });
      }
    }

    for (const [varName, writers] of Object.entries(varWriters)) {
      if (writers.length > 1) {
        // Multiple functions write same variable — potential race condition
        const hasExternalCallWriter = writers.some(w => this.externalCalls[w.function]?.length > 0);
        if (hasExternalCallWriter) {
          conflicts.push({
            variable: varName,
            writers,
            risk: 'State variable written by multiple functions, at least one after external call — reentrancy risk',
          });
        }
      }
    }
    return conflicts;
  }

  _findCallChainRisks(skillName) {
    const risks = [];

    // Find functions that call external contracts AND are called by other functions
    for (const [fnKey, calls] of Object.entries(this.externalCalls)) {
      if (calls.length === 0) continue;

      // Check if this function is reachable from a public entry point
      const [contract, fn] = fnKey.split('.');
      const reentrancyRisk = calls.some(c => c.method === 'call' || c.method === 'delegatecall');

      if (reentrancyRisk) {
        // Check if state is written after call
        const writes = this.stateWrites[fnKey] || [];
        const writesAfterCall = writes.filter(w => w.op === '=' || w.op === '+=' || w.op === '-=');

        if (writesAfterCall.length > 0) {
          risks.push({
            path: fnKey,
            callChain: calls.map(c => `${c.target}.${c.method}()`),
            stateWritesAfter: writesAfterCall.map(w => w.var),
            risk: `CEI violation: ${fnKey} calls external then writes ${writesAfterCall.map(w => w.var).join(', ')}`,
          });
        }
      }
    }

    return risks;
  }

  _findAccessGaps() {
    const gaps = [];
    for (const [fnKey, _] of Object.entries(this.stateWrites)) {
      const [contract, fn] = fnKey.split('.');
      const findings = this.getFindingsForFunction(fn);
      const hasAccessGap = findings.some(f => f.skill === 'access-control' || f.skill === 'symbolic-execution');
      if (hasAccessGap) {
        gaps.push({ function: fnKey, findings: findings.filter(f => f.skill === 'access-control') });
      }
    }
    return gaps;
  }

  _isVault(c) { return /vault|pool|staking|yield/i.test(c.name) || (c.stateVariables || []).some(v => /share|exchangeRate/i.test(v.name)); }
  _isProxy(c) { return /proxy|upgrade/i.test(c.name) || (c.inheritance || []).some(i => /proxy|uups/i.test(i)); }
  _isToken(c) { return /token|erc20|erc721/i.test(c.name) || (c.inheritance || []).some(i => /erc20|erc721/i.test(i)); }

  getStats() {
    return {
      totalFindings: this.findings.length,
      contractsTracked: Object.keys(this.contractContext).length,
      taintSources: Object.keys(this.taintMap).length,
      stateWriteConflicts: this._findStateWriteConflicts().length,
      callChainRisks: this._findCallChainRisks('all').length,
      knownPatterns: Object.keys(this.knownPatterns).length,
    };
  }
}

module.exports = SharedState;
