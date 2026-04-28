/**
 * Dynamic Severity Scoring
 * Calculates severity based on contract context: TVL, visibility, state mutability,
 * function accessibility, and exploitability rather than hardcoded per-skill values.
 */

class DynamicSeverity {
  constructor(opts = {}) {
    this.tvlData = opts.tvlData || {}; // { protocol: tvl_usd }
    this.severityThresholds = {
      critical: { minScore: 80 },
      high: { minScore: 55 },
      medium: { minScore: 30 },
      low: { minScore: 10 },
      info: { minScore: 0 },
    };
  }

  score(finding, contract) {
    const factors = {
      fundExposure: this._fundExposure(finding, contract),
      exploitability: this._exploitability(finding, contract),
      accessVector: this._accessVector(finding, contract),
      stateImpact: this._stateImpact(finding, contract),
      crossProtocol: this._crossProtocol(finding),
    };

    const rawScore = Object.values(factors).reduce((a, b) => a + b, 0);
    const normalizedScore = Math.min(100, rawScore);

    const severity = this._classify(normalizedScore);
    return {
      severity,
      score: normalizedScore,
      factors,
      originalSeverity: finding.severity,
      upgraded: this._severityRank(severity) > this._severityRank(finding.severity),
      reasoning: this._reasoning(factors, severity),
    };
  }

  scoreAll(findings, contracts) {
    const contractMap = {};
    for (const c of contracts) {
      if (c.name) contractMap[c.name] = c;
    }
    return findings.map(f => {
      const contract = contractMap[f.contract] || {};
      return { ...f, dynamicSeverity: this.score(f, contract) };
    });
  }

  _fundExposure(finding, contract) {
    let score = 0;
    const title = (finding.title || '').toLowerCase();
    const skill = (finding.skill || '').toLowerCase();

    // Direct fund drain patterns
    if (title.includes('drain') || title.includes('steal') || title.includes('sweep')) score += 25;
    if (skill.includes('reentrancy') || skill.includes('flash-loan') || skill.includes('overflow')) score += 20;
    if (skill.includes('access-control') || skill.includes('delegatecall')) score += 15;

    // Payable functions handling ETH/tokens
    const fn = (contract.functions || []).find(f => f.name === finding.functionName);
    if (fn && fn.mutability === 'payable') score += 10;

    // State variables holding balances
    const balanceVars = (contract.stateVariables || []).filter(v =>
      /balance|deposit|share|supply|reserve|collateral/i.test(v.name)
    );
    score += Math.min(10, balanceVars.length * 3);

    // TVL context
    const tvl = this.tvlData[contract.name] || 0;
    if (tvl > 1_000_000) score += 10;
    else if (tvl > 100_000) score += 5;

    return Math.min(35, score);
  }

  _exploitability(finding, contract) {
    let score = 0;
    const skill = (finding.skill || '').toLowerCase();

    // Single-transaction exploits are more dangerous
    if (skill.includes('flash-loan') || skill.includes('reentrancy')) score += 15;
    if (skill.includes('front-running')) score += 8; // requires MEV

    // External/public functions are directly callable
    const fn = (contract.functions || []).find(f => f.name === finding.functionName);
    if (fn) {
      if (fn.visibility === 'external' || fn.visibility === 'public') score += 10;
      if (fn.mutability === 'nonpayable' || fn.mutability === 'payable') score += 5;
    }

    // No access control on function
    if (skill.includes('access-control')) score += 10;

    // Known exploit patterns
    if (finding.evidence && finding.evidence.includes('PoC')) score += 5;

    return Math.min(25, score);
  }

  _accessVector(finding, contract) {
    let score = 0;
    const skill = (finding.skill || '').toLowerCase();

    // Anyone can exploit
    if (skill.includes('reentrancy') || skill.includes('flash-loan') || skill.includes('front-running')) score += 15;
    // Requires specific role but role is misconfigured
    if (skill.includes('access-control')) score += 10;
    // Requires token holder position
    if (skill.includes('erc4626') || skill.includes('donation') || skill.includes('rounding')) score += 8;
    // Requires governance/protocol context
    if (skill.includes('proxy-upgrade') || skill.includes('bridge')) score += 5;

    return Math.min(15, score);
  }

  _stateImpact(finding, contract) {
    let score = 0;
    const title = (finding.title || '').toLowerCase();

    // State corruption
    if (title.includes('storage') || title.includes('collision') || title.includes('overwrite')) score += 10;
    // Permanent lock
    if (title.includes('freeze') || title.includes('lock') || title.includes('dos')) score += 8;
    // Accounting break
    if (title.includes('overflow') || title.includes('underflow') || title.includes('rounding')) score += 10;
    // Privilege escalation
    if (title.includes('takeover') || title.includes('owner') || title.includes('upgrade')) score += 8;

    return Math.min(15, score);
  }

  _crossProtocol(finding) {
    let score = 0;
    const skill = (finding.skill || '').toLowerCase();

    // Affects multiple protocols
    if (skill.includes('oracle') || skill.includes('bridge')) score += 10;
    if (skill.includes('read-only-reentrancy')) score += 8;
    if (skill.includes('flash-loan')) score += 5;

    return Math.min(10, score);
  }

  _classify(score) {
    if (score >= 80) return 'critical';
    if (score >= 55) return 'high';
    if (score >= 30) return 'medium';
    if (score >= 10) return 'low';
    return 'info';
  }

  _severityRank(s) {
    return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] || 0;
  }

  _reasoning(factors, severity) {
    const parts = [];
    if (factors.fundExposure >= 20) parts.push('high fund exposure');
    if (factors.exploitability >= 15) parts.push('easily exploitable');
    if (factors.accessVector >= 10) parts.push('no special access required');
    if (factors.stateImpact >= 8) parts.push('critical state impact');
    if (factors.crossProtocol >= 8) parts.push('cross-protocol impact');
    return parts.length ? `Scored ${severity} due to: ${parts.join(', ')}` : `Scored ${severity}`;
  }
}

module.exports = DynamicSeverity;
