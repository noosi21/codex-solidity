const chalk = require('chalk');
const ora = require('ora');
const fs = require('fs');
const path = require('path');
const Parser = require('./parser');
const SkillLoader = require('./skill-loader');
const ImpactEngine = require('./impact-engine');
const ReportGenerator = require('./report-generator');

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

    // Phase 3: Report
    console.log(chalk.cyan.bold('\n📊 Phase 3: Generating reports...\n'));
    await this._generateReports();
    this._printFinalSummary();
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
