const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor(opts) {
    this.inputPath = opts.input;
    this.outputDir = opts.output || './audit-reports';
    this.format = opts.format || 'html';
  }

  async generate() {
    const data = JSON.parse(fs.readFileSync(this.inputPath, 'utf8'));
    if (!fs.existsSync(this.outputDir)) fs.mkdirSync(this.outputDir, { recursive: true });
    const base = path.basename(this.inputPath, '.json');
    if (this.format === 'json') {
      fs.writeFileSync(path.join(this.outputDir, base + '.json'), JSON.stringify(data, null, 2));
    } else if (this.format === 'md') {
      fs.writeFileSync(path.join(this.outputDir, base + '.md'), this._markdown(data));
    } else {
      fs.writeFileSync(path.join(this.outputDir, base + '.html'), this._html(data));
    }
  }

  _markdown(data) {
    let md = `# Codex Solidity Audit Report\n\n`;
    md += `**Target:** ${data.target}\n`;
    md += `**Date:** ${data.timestamp}\n`;
    md += `**Compiler:** ${data.compiler}\n`;
    md += `**Network:** ${data.network}\n\n`;
    md += `## Summary\n\n| Severity | Count |\n|----------|-------|\n`;
    for (const [sev, count] of Object.entries(data.summary)) md += `| ${sev.toUpperCase()} | ${count} |\n`;
    md += `\n## Contracts Analyzed\n\n`;
    for (const c of data.contracts) {
      if (c.error) { md += `- ❌ ${c.file}: ${c.error}\n`; continue; }
      md += `- **${c.file}** (pragma: ${c.pragma || 'unknown'})\n`;
      for (const co of c.contracts || []) md += `  - ${co.type} ${co.name} (${co.functions?.length || 0} functions, ${co.stateVariables?.length || 0} state vars)\n`;
    }
    md += `\n## Findings\n\n`;
    for (const f of data.findings) {
      md += `### [${f.severity.toUpperCase()}] ${f.title}\n\n`;
      if (f.contract) md += `- **Contract:** ${f.contract}\n`;
      if (f.function) md += `- **Function:** ${f.function}\n`;
      md += `- **Impact:** ${f.impact || 'N/A'}\n`;
      md += `- **Remediation:** ${f.remediation || 'N/A'}\n\n`;
      if (f.evidence) md += `**Evidence:**\n\`\`\`solidity\n${typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2)}\n\`\`\`\n\n`;
      if (f.poc) md += `**PoC:**\n\`\`\`solidity\n${typeof f.poc === 'string' ? f.poc : JSON.stringify(f.poc, null, 2)}\n\`\`\`\n\n`;
    }
    return md;
  }

  _html(data) {
    const severityColor = { critical: '#dc2626', high: '#ef4444', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280' };
    const findingsHtml = data.findings.map(f => `
      <div class="finding" style="border-left:4px solid ${severityColor[f.severity]||'#6b7280'};padding:16px;margin:12px 0;background:#1e1e2e;border-radius:8px;">
        <h3 style="color:${severityColor[f.severity]};margin:0 0 8px">[${f.severity.toUpperCase()}] ${f.title}</h3>
        ${f.contract ? `<p><strong>Contract:</strong> ${f.contract}</p>` : ''}
        ${f.function ? `<p><strong>Function:</strong> ${f.function}</p>` : ''}
        <p><strong>Impact:</strong> ${f.impact || 'N/A'}</p>
        <p><strong>Remediation:</strong> ${f.remediation || 'N/A'}</p>
        ${f.evidence ? `<details><summary>Evidence</summary><pre style="background:#111;padding:12px;border-radius:4px;overflow-x:auto;color:#e2e8f0">${this._esc(typeof f.evidence==='string'?f.evidence:JSON.stringify(f.evidence,null,2))}</pre></details>` : ''}
        ${f.poc ? `<details><summary>PoC / Exploit Contract</summary><pre style="background:#111;padding:12px;border-radius:4px;overflow-x:auto;color:#e2e8f0">${this._esc(typeof f.poc==='string'?f.poc:JSON.stringify(f.poc,null,2))}</pre></details>` : ''}
      </div>`).join('');

    return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Codex Solidity Audit Report</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#0f0f1a;color:#e2e8f0;padding:24px}
.container{max-width:1100px;margin:0 auto}h1{color:#06b6d4;border-bottom:2px solid #06b6d4;padding-bottom:12px;margin-bottom:24px}
.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:24px 0}
.stat{text-align:center;padding:16px;border-radius:8px;background:#1e1e2e}
.stat .count{font-size:2em;font-weight:bold}h2{color:#38bdf8;margin:24px 0 12px}
pre{white-space:pre-wrap;word-break:break-all}</style></head>
<body><div class="container">
<h1>⛓️ Codex Solidity Audit Report</h1>
<p><strong>Target:</strong> ${data.target} | <strong>Compiler:</strong> ${data.compiler} | <strong>Network:</strong> ${data.network} | <strong>Date:</strong> ${data.timestamp}</p>
<div class="summary">
${Object.entries(data.summary).map(([s,c])=>`<div class="stat"><div class="count" style="color:${severityColor[s]}">${c}</div><div>${s.toUpperCase()}</div></div>`).join('')}
</div>
<h2>Findings</h2>
${findingsHtml || '<p>No findings.</p>'}
</div></body></html>`;
  }

  _esc(s) { return s?.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') || ''; }
}

module.exports = ReportGenerator;
