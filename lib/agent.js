const chalk = require('chalk');
const ora = require('ora');
const fs = require('fs');
const path = require('path');
const Parser = require('./parser');
const SkillLoader = require('./skill-loader');
const ImpactEngine = require('./impact-engine');
const ReportGenerator = require('./report-generator');
const { SWCRegistry, DeFiLlamaClient } = require('./mcp');
const FoundryPoCGenerator = require('./foundry-poc');
const CorrelationEngine = require('./correlation-engine');
const DynamicSeverity = require('./dynamic-severity');
const ExternalToolParser = require('./external-tool-parser');
const CIIntegration = require('./ci-integration');
const DiffAuditor = require('./diff-auditor');
const InteractiveMode = require('./interactive-mode');

class Agent {
  constructor(opts) {
    this.target = opts.target;
    this.outputDir = opts.output || './audit-reports';
    this.compiler = opts.compiler || '0.8.19';
    this.network = opts.network || 'mainnet';
    this.skillNames = opts.skills || 'all';
    this.exclude = opts.exclude || '';
    this.results = {
      target: this.target,
      timestamp: new Date().toISOString(),
      compiler: this.compiler,
      network: this.network,
      contracts: [],
      findings: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    };
    this.parser = new Parser();
    this.loader = new SkillLoader();
    this.impact = new ImpactEngine();

    // Load config.toml
    this.agentConfig = this._loadConfigToml();

    // Load AGENTS.md durable instructions
    this.agentsMd = this._loadAgentsMd();

    // MCP intelligence
    this.swcRegistry = new SWCRegistry();
    this.defiLlama = new DeFiLlamaClient();

    // New engine modules
    this.foundryPoc = new FoundryPoCGenerator({ outputDir: path.join(this.outputDir, 'pocs'), solidityVersion: this.compiler });
    this.correlationEngine = new CorrelationEngine();
    this.dynamicSeverity = new DynamicSeverity();
    this.externalToolParser = new ExternalToolParser();
    this.ciIntegration = new CIIntegration({ failOn: opts.failOn || 'high' });
    this.diffAuditor = new DiffAuditor({ parser: this.parser });

    // Mode flags
    this.ciMode = opts.ci || false;
    this.interactiveMode = opts.interactive || false;
    this.diffRef = opts.diff || null;
  }

  _loadConfigToml() {
    const configPath = path.join(__dirname, '..', 'config.toml');
    if (!fs.existsSync(configPath)) return {};
    try {
      const content = fs.readFileSync(configPath, 'utf8');
      const config = {};
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('[')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx === -1) continue;
        const key = trimmed.substring(0, eqIdx).trim();
        let val = trimmed.substring(eqIdx + 1).trim().replace(/^"|"$/g, '');
        if (val === 'true') val = true;
        else if (val === 'false') val = false;
        else if (!isNaN(val) && val !== '') val = Number(val);
        config[key] = val;
      }
      return config;
    } catch { return {}; }
  }

  _loadAgentsMd() {
    const agentsPath = path.join(__dirname, '..', 'AGENTS.md');
    if (!fs.existsSync(agentsPath)) return null;
    try { return fs.readFileSync(agentsPath, 'utf8'); }
    catch { return null; }
  }

  async run() {
    // Phase 1: Parse contracts
    const parseSpinner = ora('Phase 1: Parsing Solidity contracts').start();
    try {
      const stat = fs.statSync(this.target);
      if (stat.isDirectory()) {
        this.results.contracts = this.parser.parseProject(this.target, this.exclude);
      } else if (this.target.endsWith('.sol')) {
        this.results.contracts = [this.parser.parseFile(this.target)];
      } else {
        parseSpinner.fail('Target must be a .sol file or directory');
        process.exit(1);
      }
      const contractCount = this.results.contracts.filter(c => !c.error).length;
      const funcCount = this.results.contracts.reduce((n, c) => n + (c.contracts?.reduce((m, co) => m + co.functions.length, 0) || 0), 0);
      parseSpinner.succeed(chalk.green(`Phase 1: Parsed ${contractCount} file(s), ${funcCount} functions`));
    } catch (err) {
      parseSpinner.fail(chalk.red('Phase 1: Parse failed — ' + err.message));
      return;
    }

    // Diff filtering: only audit changed functions
    if (this.diffRef) {
      const diffSpinner = ora('Diff: Analyzing changed functions').start();
      const [baseRef, headRef] = this.diffRef.split('...');
      const diffSummary = this.diffAuditor.getDiffSummary(baseRef, headRef);
      const changedFunctions = this.diffAuditor.getChangedFunctions(baseRef, headRef);
      this.results.contracts = this.diffAuditor.filterContractsToAudit(this.results.contracts, changedFunctions);
      const remaining = this.results.contracts.filter(c => !c.error).length;
      diffSpinner.succeed(chalk.cyan(`Diff: ${diffSummary.changedFiles} files changed, ${diffSummary.changedFunctions} functions modified — auditing ${remaining} file(s)`));
      this.results.diffSummary = diffSummary;
    }

    // Phase 2: Run skills
    const skills = this._resolveSkills();
    console.log(chalk.cyan.bold(`\n⚔️  Phase 2: Running ${skills.length} skill(s)...\n`));

    for (const skill of skills) {
      const skillSpinner = ora(`Running: ${skill.name} — ${skill.description}`).start();
      try {
        const ctx = {
          contracts: this.results.contracts,
          compiler: this.compiler,
          network: this.network,
          impactEngine: this.impact,
          parser: this.parser,
        };
        const findings = await skill.execute(ctx);
        if (findings && findings.length > 0) {
          for (const f of findings) {
            this.results.findings.push(f);
            this.results.summary[f.severity] = (this.results.summary[f.severity] || 0) + 1;
          }
          skillSpinner.succeed(chalk.green(`${skill.name}: ${findings.length} finding(s)`));
          this._printFindings(findings);
        } else {
          skillSpinner.info(chalk.yellow(`${skill.name}: No findings`));
        }
      } catch (err) {
        skillSpinner.fail(chalk.red(`${skill.name}: Error — ${err.message}`));
      }
    }

    // Phase 2.5: Post-processing
    // Dynamic severity scoring
    if (this.results.findings.length > 0) {
      const allContracts = this.results.contracts.flatMap(f => f.contracts || []);
      this.results.findings = this.dynamicSeverity.scoreAll(this.results.findings, allContracts);

      // Cross-skill correlation
      this.results.correlations = this.correlationEngine.correlate(this.results.findings);
      if (this.results.correlations.length > 0) {
        console.log(chalk.magenta.bold(`\n🔗 Cross-Skill Correlations: ${this.results.correlations.length} combined exploit paths detected`));
        for (const c of this.results.correlations) {
          console.log(`   ${chalk.red('[' + c.severity.toUpperCase() + ']')} ${c.name} (${c.skills.join(' + ')})`);
        }
      }

      // Foundry PoC generation for critical/high
      const pocs = this.foundryPoc.generate(this.results.findings, allContracts);
      if (pocs.length > 0) {
        const manifest = this.foundryPoc.save(pocs);
        console.log(chalk.cyan.bold(`\n📝 Generated ${pocs.length} Foundry PoC(s)`));
        for (const p of manifest) {
          console.log(`   ${chalk.green(p.file)} [${p.severity}] ${p.title}`);
        }
      }
    }

    // Phase 3: Report
    console.log(chalk.cyan.bold('\n📊 Phase 3: Generating reports...\n'));
    await this._generateReports();
    this._printFinalSummary();

    // Interactive mode
    if (this.interactiveMode && this.results.findings.length > 0) {
      const interactive = new InteractiveMode({
        findings: this.results.findings,
        correlations: this.results.correlations || [],
        mcpClient: { swcRegistry: this.swcRegistry, defiLlama: this.defiLlama },
        severityScorer: this.dynamicSeverity,
        foundryPoc: this.foundryPoc,
      });
      await interactive.start();
    }

    // CI mode: exit code
    if (this.ciMode) {
      const exitCode = this.ciIntegration.getExitCode(this.results.findings);
      if (exitCode !== 0) {
        console.log(chalk.red.bold(`\n⛔ CI FAIL: Findings at or above "${this.ciIntegration.failOn}" severity threshold`));
      } else {
        console.log(chalk.green.bold('\n✅ CI PASS: No findings above severity threshold'));
      }
      process.exit(exitCode);
    }
  }

  async runSingle(skill) {
    const stat = fs.statSync(this.target);
    this.results.contracts = stat.isDirectory()
      ? this.parser.parseProject(this.target, this.exclude)
      : [this.parser.parseFile(this.target)];

    const ctx = {
      contracts: this.results.contracts,
      compiler: this.compiler,
      network: this.network,
      impactEngine: this.impact,
      parser: this.parser,
    };
    const findings = await skill.execute(ctx);
    this.results.findings = findings || [];
    for (const f of this.results.findings) {
      this.results.summary[f.severity] = (this.results.summary[f.severity] || 0) + 1;
    }
    this._printFindings(this.results.findings);
    await this._generateReports();
    this._printFinalSummary();
  }

  _resolveSkills() {
    if (this.skillNames === 'all') return this.loader.getAllSkills();
    return this.skillNames.split(',').map(name => {
      const skill = this.loader.getSkill(name.trim());
      if (!skill) console.log(chalk.yellow(`⚠ Skill "${name}" not found, skipping`));
      return skill;
    }).filter(Boolean);
  }

  _printFindings(findings) {
    for (const f of findings) {
      const color = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue', info: 'gray' }[f.severity] || 'white';
      console.log(`   ${chalk[color].bold(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
      if (f.contract) console.log(`   ${chalk.gray('Contract:')} ${f.contract}`);
      if (f.impact) console.log(`   ${chalk.gray('Impact:')} ${f.impact}`);
      console.log();
    }
  }

  async _generateReports() {
    if (!fs.existsSync(this.outputDir)) fs.mkdirSync(this.outputDir, { recursive: true });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const base = path.join(this.outputDir, `audit-${timestamp}`);
    fs.writeFileSync(base + '.json', JSON.stringify(this.results, null, 2));
    const reporter = new ReportGenerator({ input: base + '.json', output: this.outputDir, format: 'md' });
    await reporter.generate();
    const reporterHtml = new ReportGenerator({ input: base + '.json', output: this.outputDir, format: 'html' });
    await reporterHtml.generate();
  }

  _printFinalSummary() {
    const s = this.results.summary;
    console.log(chalk.cyan.bold('\n═══════════════════════════════════════════'));
    console.log(chalk.cyan.bold('  AUDIT COMPLETE — Summary'));
    console.log(chalk.cyan.bold('═══════════════════════════════════════════'));
    console.log(`  ${chalk.red.bold('CRITICAL:')} ${s.critical || 0}`);
    console.log(`  ${chalk.red.bold('HIGH:     ')} ${s.high || 0}`);
    console.log(`  ${chalk.yellow.bold('MEDIUM:   ')} ${s.medium || 0}`);
    console.log(`  ${chalk.blue.bold('LOW:      ')} ${s.low || 0}`);
    console.log(`  ${chalk.gray.bold('INFO:     ')} ${s.info || 0}`);
    console.log(chalk.cyan.bold('═══════════════════════════════════════════\n'));
  }
}

module.exports = Agent;
