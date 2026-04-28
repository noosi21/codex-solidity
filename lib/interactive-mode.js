/**
 * Interactive Mode — REPL for drilling into findings
 * Allows auditors to explore findings, request PoC details, refine severity, and query MCP.
 */

const readline = require('readline');

class InteractiveMode {
  constructor(opts = {}) {
    this.findings = opts.findings || [];
    this.correlations = opts.correlations || [];
    this.mcpClient = opts.mcpClient || null;
    this.severityScorer = opts.severityScorer || null;
    this.foundryPoc = opts.foundryPoc || null;
    this.rl = null;
  }

  async start() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: 'codex> ',
    });

    console.log('\n🔍 Codex Solidity — Interactive Audit Mode');
    console.log('Type "help" for commands, "exit" to quit\n');
    this._printSummary();
    this.rl.prompt();

    return new Promise((resolve) => {
      this.rl.on('line', async (line) => {
        const [cmd, ...args] = line.trim().split(/\s+/);
        try {
          await this._handleCommand(cmd, args);
        } catch (err) {
          console.log(`Error: ${err.message}`);
        }
        this.rl.prompt();
      });

      this.rl.on('close', () => {
        console.log('\nExiting interactive mode.');
        resolve(this.findings);
      });
    });
  }

  async _handleCommand(cmd, args) {
    const commands = {
      help: () => this._help(),
      list: () => this._listFindings(args),
      show: () => this._showFinding(args),
      severity: () => this._reScore(args),
      poc: () => this._generatePoC(args),
      mcp: () => this._queryMcp(args),
      correlate: () => this._showCorrelations(),
      filter: () => this._filterFindings(args),
      dismiss: () => this._dismissFinding(args),
      export: () => this._exportFindings(args),
      summary: () => this._printSummary(),
      exit: () => this.rl.close(),
      quit: () => this.rl.close(),
    };

    const handler = commands[cmd];
    if (handler) {
      await handler();
    } else {
      console.log(`Unknown command: ${cmd}. Type "help" for available commands.`);
    }
  }

  _help() {
    console.log(`
Available commands:
  list [severity]          List findings (optional filter: critical, high, medium, low, info)
  show <id>               Show detailed finding by index (1-based)
  severity <id>           Re-score finding with dynamic severity calculator
  poc <id>                Generate Foundry PoC for finding
  mcp <query> [source]    Query MCP intelligence (swc, defillama)
  correlate               Show cross-skill correlations
  filter <skill|severity> Filter findings by skill name or severity
  dismiss <id>            Dismiss a finding (mark as info)
  export [format]         Export current findings (json, md)
  summary                 Show audit summary
  help                    Show this help
  exit / quit             Exit interactive mode
`);
  }

  _printSummary() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    console.log(`\n📊 Audit Summary: ${this.findings.length} findings`);
    console.log(`   Critical: ${counts.critical}  High: ${counts.high}  Medium: ${counts.medium}  Low: ${counts.low}  Info: ${counts.info}`);
    if (this.correlations.length > 0) {
      console.log(`   🔗 Correlations: ${this.correlations.length} combined exploit paths detected`);
    }
    console.log();
  }

  _listFindings(args) {
    const filter = args[0];
    const filtered = filter
      ? this.findings.filter(f => f.severity === filter || f.skill === filter)
      : this.findings;

    if (filtered.length === 0) {
      console.log('No findings match the filter.');
      return;
    }

    filtered.forEach((f, i) => {
      const idx = this.findings.indexOf(f) + 1;
      const sev = this._severityColor(f.severity);
      console.log(`  ${sev} #${idx} [${f.severity.toUpperCase()}] ${f.title} (${f.skill || 'unknown'})`);
    });
    console.log(`\n  Total: ${filtered.length} findings\n`);
  }

  _showFinding(args) {
    const idx = parseInt(args[0]) - 1;
    if (idx < 0 || idx >= this.findings.length) {
      console.log('Invalid finding index. Use "list" to see indices.');
      return;
    }
    const f = this.findings[idx];
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  #${idx + 1} ${f.title}`);
    console.log(`${'='.repeat(60)}`);
    console.log(`  Severity:   ${f.severity.toUpperCase()}`);
    console.log(`  Skill:      ${f.skill || 'unknown'}`);
    console.log(`  Contract:   ${f.contract || 'unknown'}`);
    console.log(`  Function:   ${f.functionName || f.function || 'unknown'}`);
    console.log(`  Evidence:   ${f.evidence || 'N/A'}`);
    console.log(`  Impact:     ${f.impact || 'N/A'}`);
    console.log(`  Remediation:${f.remediation || 'N/A'}`);
    if (f.dynamicSeverity) {
      console.log(`  Dynamic Score: ${f.dynamicSeverity.score}/100 (${f.dynamicSeverity.reasoning})`);
    }
    if (f.poc) {
      console.log(`  PoC:        Available (use "poc ${idx + 1}" to generate Foundry test)`);
    }
    console.log(`${'='.repeat(60)}\n`);
  }

  async _reScore(args) {
    const idx = parseInt(args[0]) - 1;
    if (idx < 0 || idx >= this.findings.length) {
      console.log('Invalid finding index.');
      return;
    }
    if (!this.severityScorer) {
      console.log('Dynamic severity scorer not available.');
      return;
    }
    const f = this.findings[idx];
    const result = this.severityScorer.score(f, {});
    f.dynamicSeverity = result;
    if (result.upgraded) {
      console.log(`\n  ⬆️  Severity UPGRADED: ${f.severity} → ${result.severity} (score: ${result.score}/100)`);
    } else {
      console.log(`\n  Severity: ${result.severity} (score: ${result.score}/100) — ${result.reasoning}`);
    }
    console.log(`  Factors: fundExposure=${result.factors.fundExposure} exploitability=${result.factors.exploitability} accessVector=${result.factors.accessVector} stateImpact=${result.factors.stateImpact} crossProtocol=${result.factors.crossProtocol}\n`);
  }

  async _generatePoC(args) {
    const idx = parseInt(args[0]) - 1;
    if (idx < 0 || idx >= this.findings.length) {
      console.log('Invalid finding index.');
      return;
    }
    if (!this.foundryPoc) {
      console.log('Foundry PoC generator not available.');
      return;
    }
    const f = this.findings[idx];
    const pocs = this.foundryPoc.generate([f], []);
    if (pocs.length > 0) {
      console.log(`\n  📝 Generated Foundry PoC: ${pocs[0].fileName}`);
      console.log(`  Preview:\n${pocs[0].content.substring(0, 500)}...\n`);
    } else {
      console.log('Could not generate PoC for this finding.');
    }
  }

  async _queryMcp(args) {
    if (!this.mcpClient) {
      console.log('MCP client not available.');
      return;
    }
    const query = args[0];
    const source = args[1] || 'all';
    if (!query) {
      console.log('Usage: mcp <query> [source: swc, defillama, all]');
      return;
    }
    console.log(`Querying MCP: "${query}" (source: ${source})...`);
    try {
      if (source === 'all' || source === 'swc') {
        const results = this.mcpClient.swcRegistry?.search(query) || [];
        if (results.length > 0) {
          console.log(`  SWC: ${results[0].id} — ${results[0].title}`);
        }
      }
      if (source === 'all' || source === 'defillama') {
        const results = await this.mcpClient.defiLlama?.searchProtocol(query) || [];
        if (results.length > 0) {
          console.log(`  DeFiLlama: ${results[0].name} — TVL: $${(results[0].tvl || 0).toLocaleString()}`);
        }
      }
    } catch (err) {
      console.log(`  MCP query failed: ${err.message}`);
    }
    console.log();
  }

  _showCorrelations() {
    if (this.correlations.length === 0) {
      console.log('No cross-skill correlations detected.');
      return;
    }
    console.log(`\n🔗 Cross-Skill Correlations (${this.correlations.length}):\n`);
    for (const c of this.correlations) {
      const sev = this._severityColor(c.severity);
      console.log(`  ${sev} ${c.name}`);
      console.log(`     Skills: ${c.skills.join(' + ')}`);
      console.log(`     Pattern: ${c.pattern}`);
      console.log(`     Combined Impact: ${c.combinedImpact}`);
      console.log(`     Recommendation: ${c.recommendation}\n`);
    }
  }

  _filterFindings(args) {
    const filter = args[0];
    if (!filter) {
      console.log('Usage: filter <skill-name|severity>');
      return;
    }
    this._listFindings([filter]);
  }

  _dismissFinding(args) {
    const idx = parseInt(args[0]) - 1;
    if (idx < 0 || idx >= this.findings.length) {
      console.log('Invalid finding index.');
      return;
    }
    const f = this.findings[idx];
    const oldSev = f.severity;
    f.severity = 'info';
    f.dismissed = true;
    console.log(`  Finding #${idx + 1} dismissed: ${oldSev} → info\n`);
  }

  _exportFindings(args) {
    const format = args[0] || 'json';
    if (format === 'json') {
      console.log(JSON.stringify(this.findings, null, 2));
    } else {
      for (const f of this.findings) {
        console.log(`## ${f.title}\n- Severity: ${f.severity}\n- Contract: ${f.contract}\n- Impact: ${f.impact}\n`);
      }
    }
  }

  _severityColor(severity) {
    const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
    return icons[severity] || '⚪';
  }
}

module.exports = InteractiveMode;
