/**
 * External Tool Output Parser
 * Normalizes Slither, Aderyn, and other tool outputs into Codex finding format.
 */

class ExternalToolParser {
  parseSlither(jsonOutput) {
    const findings = [];
    try {
      const data = typeof jsonOutput === 'string' ? JSON.parse(jsonOutput) : jsonOutput;
      const detectors = data.results?.detectors || data.detectors || [];
      for (const d of detectors) {
        findings.push({
          title: `Slither: ${d.check || d.detector || 'Unknown'}`,
          severity: this._mapSlitherSeverity(d.impact || d.severity),
          contract: this._extractContractFromFirst(d.elements),
          functionName: this._extractFunctionFromFirst(d.elements),
          evidence: d.description || d.first_markdown_element || '',
          impact: d.description || '',
          remediation: d.recommendation || '',
          skill: this._mapSlitherToSkill(d.check || d.detector || ''),
          source: 'slither',
          sourceId: d.id,
          confidence: d.confidence || 'medium',
        });
      }
    } catch { /* invalid JSON */ }
    return findings;
  }

  parseAderyn(jsonOutput) {
    const findings = [];
    try {
      const data = typeof jsonOutput === 'string' ? JSON.parse(jsonOutput) : jsonOutput;
      const issues = data.issues || data.vulnerabilities || [];
      for (const i of issues) {
        findings.push({
          title: `Aderyn: ${i.title || i.vulnerability_class || 'Unknown'}`,
          severity: this._mapAderynSeverity(i.severity || i.impact),
          contract: i.contract || i.location?.contract || '',
          functionName: i.function || i.location?.function || '',
          evidence: i.description || i.headline || '',
          impact: i.impact_description || i.description || '',
          remediation: i.recommendation || '',
          skill: this._mapAderynToSkill(i.title || i.vulnerability_class || ''),
          source: 'aderyn',
          sourceId: i.id,
          confidence: 'high',
        });
      }
    } catch { /* invalid JSON */ }
    return findings;
  }

  parseMythril(jsonOutput) {
    const findings = [];
    try {
      const data = typeof jsonOutput === 'string' ? JSON.parse(jsonOutput) : jsonOutput;
      const issues = data.issues || [];
      for (const i of issues) {
        findings.push({
          title: `Mythril: ${i.title || i.swcTitle || 'Unknown'}`,
          severity: this._mapMythrilSeverity(i.severity),
          contract: i.contract || '',
          functionName: i.function || '',
          evidence: i.description || '',
          impact: i.description || '',
          remediation: '',
          skill: this._mapSWCToSkill(i.swcID),
          source: 'mythril',
          sourceId: i.swcID,
          confidence: 'medium',
        });
      }
    } catch { /* invalid JSON */ }
    return findings;
  }

  parseFile(filePath) {
    const fs = require('fs');
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, 'utf8');
    if (filePath.includes('slither')) return this.parseSlither(content);
    if (filePath.includes('aderyn')) return this.parseAderyn(content);
    if (filePath.includes('mythril')) return this.parseMythril(content);
    // Try all parsers
    return [...this.parseSlither(content), ...this.parseAderyn(content), ...this.parseMythril(content)];
  }

  _mapSlitherSeverity(impact) {
    const map = { High: 'high', Medium: 'medium', Low: 'low', Informational: 'info', Optimization: 'info' };
    return map[impact] || 'medium';
  }

  _mapAderynSeverity(severity) {
    const map = { High: 'high', Medium: 'medium', Low: 'low', Informational: 'info' };
    return map[severity] || 'medium';
  }

  _mapMythrilSeverity(severity) {
    const map = { High: 'critical', Medium: 'high', Low: 'medium' };
    return map[severity] || 'medium';
  }

  _extractContractFromFirst(elements) {
    if (!elements || !elements[0]) return '';
    return elements[0].contract?.name || elements[0].name || '';
  }

  _extractFunctionFromFirst(elements) {
    if (!elements || !elements[0]) return '';
    return elements[0].function?.name || '';
  }

  _mapSlitherToSkill(check) {
    const c = (check || '').toLowerCase();
    if (c.includes('reentrancy')) return 'reentrancy';
    if (c.includes('access') || c.includes('owner')) return 'access-control';
    if (c.includes('overflow') || c.includes('underflow')) return 'overflow';
    if (c.includes('unchecked') || c.includes('return')) return 'unchecked-returns';
    if (c.includes('shadow')) return 'shadowing';
    if (c.includes('delegatecall')) return 'delegatecall';
    if (c.includes('front-running') || c.includes('erc20')) return 'front-running';
    if (c.includes('timestamp')) return 'timestamp-dependence';
    if (c.includes('assembly')) return 'assembly-issues';
    if (c.includes('pragma')) return 'pragma-bugs';
    if (c.includes('storage')) return 'storage-pointer';
    return 'unknown';
  }

  _mapAderynToSkill(title) {
    const t = (title || '').toLowerCase();
    if (t.includes('reentrancy')) return 'reentrancy';
    if (t.includes('access') || t.includes('owner')) return 'access-control';
    if (t.includes('overflow')) return 'overflow';
    if (t.includes('unchecked')) return 'unchecked-returns';
    if (t.includes('centralized') || t.includes('privilege')) return 'access-control';
    if (t.includes('delegatecall')) return 'delegatecall';
    if (t.includes('shadow')) return 'shadowing';
    if (t.includes('pragma')) return 'pragma-bugs';
    return 'unknown';
  }

  _mapSWCToSkill(swcId) {
    const map = {
      SWC_101: 'reentrancy', SWC_102: 'overflow', SWC_103: 'pragma-bugs',
      SWC_104: 'unchecked-returns', SWC_105: 'access-control', SWC_106: 'access-control',
      SWC_107: 'reentrancy', SWC_108: 'access-control', SWC_109: 'unchecked-returns',
      SWC_110: 'shadowing', SWC_111: 'access-control', SWC_112: 'delegatecall',
      SWC_113: 'delegatecall', SWC_114: 'timestamp-dependence', SWC_115: 'access-control',
      SWC_116: 'timestamp-dependence', SWC_117: 'assembly-issues', SWC_118: 'assembly-issues',
      SWC_119: 'overflow', SWC_120: 'overflow', SWC_121: 'access-control',
    };
    return map[swcId] || 'unknown';
  }
}

module.exports = ExternalToolParser;
