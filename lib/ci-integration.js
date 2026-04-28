/**
 * CI/CD Integration Module
 * Provides --ci flag, exit codes based on severity threshold, and GitHub Actions workflow generation.
 */

class CIIntegration {
  constructor(opts = {}) {
    this.failOn = opts.failOn || 'high'; // critical, high, medium, low, info, never
    this.outputFormat = opts.outputFormat || 'json'; // json, sarif, github-actions
  }

  getExitCode(findings) {
    if (this.failOn === 'never') return 0;

    const severityRanks = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const threshold = severityRanks[this.failOn] || 3;

    const maxSeverity = Math.max(...findings.map(f => severityRanks[f.severity] || 0));
    return maxSeverity >= threshold ? 1 : 0;
  }

  formatGitHubActions(findings) {
    const lines = [];
    for (const f of findings) {
      const level = this._severityToGHALevel(f.severity);
      const msg = f.title.replace(/"/g, '\\"');
      const file = f.contract || '';
      const line = f.lineStart || f.line || 1;
      lines.push(`::${level} file=${file},line=${line}::${msg}`);
    }
    return lines.join('\n');
  }

  formatSARIF(findings, repoUrl) {
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'codex-solidity',
            version: '1.0.0',
            informationUri: repoUrl || 'https://github.com/noosi21/codex-solidity',
            rules: this._generateSARIFRules(findings),
          },
        },
        results: findings.map(f => this._findingToSARIFResult(f)),
      }],
    };
    return JSON.stringify(sarif, null, 2);
  }

  generateGitHubActionsWorkflow() {
    return `name: Codex Solidity Audit

on:
  push:
    branches: [main, develop]
    paths: ['**/*.sol', 'contracts/**']
  pull_request:
    paths: ['**/*.sol', 'contracts/**']

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Codex Solidity
        run: |
          git clone https://github.com/noosi21/codex-solidity /opt/codex-solidity
          cd /opt/codex-solidity && npm install

      - name: Install Slither
        run: pip install slither-analyzer

      - name: Run Codex Audit (Diff Mode)
        run: |
          node /opt/codex-solidity/bin/codex-sol.js audit \\
            -t ./contracts/ \\
            --diff base...HEAD \\
            --ci \\
            --fail-on high \\
            --output ./audit-results \\
            --format sarif

      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./audit-results/audit.sarif

      - name: Upload Audit Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: ./audit-results/
`;
  }

  _severityToGHALevel(severity) {
    const map = { critical: 'error', high: 'error', medium: 'warning', low: 'notice', info: 'notice' };
    return map[severity] || 'warning';
  }

  _generateSARIFRules(findings) {
    const seen = new Set();
    return findings.filter(f => {
      const key = f.skill || f.title;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).map(f => ({
      id: f.skill || f.title.replace(/[^a-zA-Z0-9-]/g, '-'),
      name: f.title,
      shortDescription: { text: f.title },
      properties: { severity: f.severity },
    }));
  }

  _findingToSARIFResult(f) {
    return {
      ruleId: f.skill || f.title.replace(/[^a-zA-Z0-9-]/g, '-'),
      level: this._severityToSARIFLevel(f.severity),
      message: { text: f.impact || f.evidence || f.title },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file || f.contract || '' },
          region: { startLine: f.lineStart || f.line || 1 },
        },
      }],
      properties: { severity: f.severity },
    };
  }

  _severityToSARIFLevel(severity) {
    const map = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'none' };
    return map[severity] || 'warning';
  }
}

module.exports = CIIntegration;
