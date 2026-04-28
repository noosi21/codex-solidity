#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');
const Agent = require('../lib/agent');
const SkillLoader = require('../lib/skill-loader');
const ReportGenerator = require('../lib/report-generator');
const Parser = require('../lib/parser');
const { SWCRegistry, DeFiLlamaClient } = require('../lib/mcp');

const BANNER = `
${chalk.cyan.bold(`
   ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██████╗ ██╗     ██╗███████╗██████╗
  ██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██╔══██╗██║     ██║██╔════╝██╔══██╗
  ██║   ██║██║  ██║███████╗███████╗███████║██║█████╗  ██████╔╝██║     ██║█████╗  ██████╔╝
  ██║   ██║██║  ██║╚════██║╚════██║██╔══██║██║██╔══╝  ██╔══██╗██║     ██║██╔══╝  ██╔══██╗
  ╚██████╔╝██████╔╝███████║███████║██║  ██║██║███████╗██║  ██║███████╗██║███████╗██║  ██║
   ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝
`)}
${chalk.yellow.bold('  ⛓️  Smart Contract & Protocol Audit Agent — Impact-Driven Vulnerability Discovery')}
${chalk.gray('  v1.0.0 | by Thabiso Noosi')}
`;

const program = new Command();

program
  .name('codex-solidity')
  .description('Codex CLI Agent for Smart Contract & Blockchain Protocol Audits')
  .version('1.0.0')
  .addHelpText('before', BANNER);

program
  .command('audit')
  .description('Run full audit on a Solidity project or contract file')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or project directory')
  .option('-s, --skills <list>', 'Comma-separated skills to run (default: all)', 'all')
  .option('-o, --output <dir>', 'Output directory for reports', './audit-reports')
  .option('-c, --config <path>', 'Path to config YAML', path.join(__dirname, '..', 'config', 'default.yaml'))
  .option('--compiler <version>', 'Solidity compiler version (e.g. 0.8.19)', '0.8.19')
  .option('--network <name>', 'Target network for context (mainnet, goerli, fork)', 'mainnet')
  .option('--exclude <list>', 'Comma-separated paths to exclude', '')
  .option('--ci', 'CI mode: exit with non-zero code if findings above threshold')
  .option('--fail-on <severity>', 'CI fail threshold: critical, high, medium, low', 'high')
  .option('--diff <ref>', 'Diff mode: only audit changed functions (e.g. main...HEAD)')
  .option('--interactive', 'Interactive REPL mode: drill into findings after audit')
  .action(async (opts) => {
    console.log(BANNER);
    const agent = new Agent(opts);
    await agent.run();
  });

program
  .command('skill')
  .description('Run a single skill against a contract')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or project directory')
  .requiredOption('-n, --name <skill>', 'Skill name (e.g. reentrancy, flash-loan, overflow)')
  .option('-o, --output <dir>', 'Output directory', './audit-reports')
  .action(async (opts) => {
    console.log(BANNER);
    const loader = new SkillLoader();
    const skill = loader.getSkill(opts.name);
    if (!skill) {
      console.log(chalk.red(`✖ Skill "${opts.name}" not found. Available: ${loader.listSkills().join(', ')}`));
      process.exit(1);
    }
    const agent = new Agent({ ...opts, skills: opts.name });
    await agent.runSingle(skill);
  });

program
  .command('parse')
  .description('Parse and display contract structure (functions, state vars, events)')
  .requiredOption('-t, --target <path>', 'Path to Solidity file')
  .action(async (opts) => {
    console.log(BANNER);
    const parser = new Parser();
    const result = parser.parseFile(opts.target);
    console.log(chalk.cyan.bold('\n📋 Contract Structure:\n'));
    console.log(JSON.stringify(result, null, 2));
  });

program
  .command('list')
  .description('List all available skills')
  .action(() => {
    console.log(BANNER);
    const loader = new SkillLoader();
    const skills = loader.getAllSkills();
    console.log(chalk.yellow.bold('\n📋 Available Skills:\n'));
    for (const s of skills) {
      console.log(`  ${chalk.green(s.name.padEnd(22))} ${chalk.gray(s.severity.padEnd(12))} ${s.description}`);
    }
    console.log();
  });

program
  .command('report')
  .description('Generate report from previous audit JSON results')
  .requiredOption('-i, --input <path>', 'Path to audit results JSON')
  .option('-f, --format <fmt>', 'Output format: html, md, json', 'html')
  .option('-o, --output <dir>', 'Output directory', './audit-reports')
  .action(async (opts) => {
    const reporter = new ReportGenerator(opts);
    await reporter.generate();
  });

program
  .command('mcp')
  .description('Query external intelligence sources (SWC Registry, DeFiLlama)')
  .requiredOption('-q, --query <query>', 'Search query (e.g. "reentrancy", protocol name)')
  .option('-s, --source <source>', 'Source: swc, defillama, all', 'all')
  .action(async (opts) => {
    console.log(BANNER);
    console.log(chalk.cyan.bold('\n🔍 MCP Intelligence Lookup\n'));

    if (opts.source === 'all' || opts.source === 'swc') {
      const swc = new SWCRegistry();
      const results = swc.lookup(opts.query);
      if (results.length > 0) {
        console.log(chalk.yellow.bold('SWC Registry Results:'));
        for (const r of results) {
          console.log(`  ${chalk.green(r.id)} ${r.name} [${r.severity}]`);
          console.log(`  ${chalk.gray(r.url)}`);
        }
      } else {
        console.log(chalk.yellow('  No SWC results found.'));
      }
      console.log();
    }

    if (opts.source === 'all' || opts.source === 'defillama') {
      const llama = new DeFiLlamaClient();
      try {
        const exploits = await llama.getExploits();
        const relevant = (exploits || []).filter(e =>
          (e.name || '').toLowerCase().includes(opts.query.toLowerCase()) ||
          (e.protocol || '').toLowerCase().includes(opts.query.toLowerCase())
        );
        if (relevant.length > 0) {
          console.log(chalk.yellow.bold('DeFiLlama Exploit History:'));
          for (const e of relevant.slice(0, 10)) {
            console.log(`  ${chalk.red('$' + (e.amount || '?'))} ${e.name || e.protocol} — ${e.chain || ''}`);
          }
        } else {
          console.log(chalk.yellow('  No DeFiLlama exploit results found.'));
        }
      } catch {
        console.log(chalk.yellow('  DeFiLlama lookup unavailable (offline mode).'));
      }
      console.log();
    }
  });

program
  .command('config')
  .description('Show current agent configuration (config.toml + AGENTS.md)')
  .action(() => {
    console.log(BANNER);
    console.log(chalk.cyan.bold('\n⚙️  Agent Configuration\n'));

    // config.toml
    const configPath = path.join(__dirname, '..', 'config.toml');
    if (fs.existsSync(configPath)) {
      console.log(chalk.yellow.bold('config.toml:'));
      console.log(chalk.gray(fs.readFileSync(configPath, 'utf8')));
    } else {
      console.log(chalk.yellow('  No config.toml found.'));
    }

    // AGENTS.md
    const agentsPath = path.join(__dirname, '..', 'AGENTS.md');
    if (fs.existsSync(agentsPath)) {
      console.log(chalk.yellow.bold('\nAGENTS.md (Durable Instructions):'));
      const content = fs.readFileSync(agentsPath, 'utf8');
      console.log(chalk.gray(content.substring(0, 500) + (content.length > 500 ? '...' : '')));
    } else {
      console.log(chalk.yellow('  No AGENTS.md found.'));
    }
    console.log();
  });

program
  .command('diff')
  .description('Show diff audit summary: changed files and functions between refs')
  .requiredOption('-b, --base <ref>', 'Base git ref (branch, commit, tag)')
  .option('-h, --head <ref>', 'Head git ref (default: working tree)')
  .action((opts) => {
    console.log(BANNER);
    const DiffAuditor = require('../lib/diff-auditor');
    const diff = new DiffAuditor();
    const summary = diff.getDiffSummary(opts.base, opts.head);
    console.log(chalk.cyan.bold('\n📊 Diff Audit Summary\n'));
    console.log(`  Base: ${summary.baseRef}`);
    console.log(`  Head: ${summary.headRef}`);
    console.log(`  Changed Solidity files: ${summary.changedFiles}`);
    for (const f of summary.solFiles) console.log(`    ${chalk.gray(f)}`);
    console.log(`  Modified functions: ${summary.changedFunctions}`);
    console.log(`  Changed state vars: ${summary.changedStateVars}`);
    console.log(`  High-risk (public/external/payable): ${summary.highRiskChanges}`);
    console.log(chalk.gray(`\n  ${summary.summary}`));
    console.log();
  });

program
  .command('import')
  .description('Import findings from external tools (Slither, Aderyn, Mythril)')
  .requiredOption('-i, --input <path>', 'Path to external tool JSON output')
  .option('-t, --tool <name>', 'Tool name: slither, aderyn, mythril, auto', 'auto')
  .action((opts) => {
    console.log(BANNER);
    const ExternalToolParser = require('../lib/external-tool-parser');
    const parser = new ExternalToolParser();
    const findings = parser.parseFile(opts.input);
    console.log(chalk.cyan.bold(`\n📋 Imported ${findings.length} findings from ${opts.input}\n`));
    for (const f of findings) {
      const color = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue', info: 'gray' }[f.severity] || 'white';
      console.log(`  ${chalk[color].bold(`[${f.severity.toUpperCase()}]`)} ${f.title} (${f.source})`);
    }
    console.log();
  });

program
  .command('ci-workflow')
  .description('Generate GitHub Actions workflow for CI audit')
  .action(() => {
    const CIIntegration = require('../lib/ci-integration');
    const ci = new CIIntegration();
    const workflow = ci.generateGitHubActionsWorkflow();
    console.log(workflow);
  });

program
  .command('fuzz')
  .description('Generate Echidna + Medusa fuzzing harnesses for contract invariants')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or project directory')
  .option('-o, --output <dir>', 'Output directory for harnesses', './audit-reports/fuzz')
  .action((opts) => {
    console.log(BANNER);
    const FuzzingEngine = require('../lib/fuzzing-engine');
    const Parser = require('../lib/parser');
    const parser = new Parser();
    const fuzzer = new FuzzingEngine({ outputDir: opts.output });
    const stat = fs.statSync(opts.target);
    const results = stat.isDirectory() ? parser.parseProject(opts.target) : [parser.parseFile(opts.target)];
    const harnesses = fuzzer.generateAll(results);
    if (harnesses.length > 0) {
      const manifest = fuzzer.save(harnesses);
      console.log(chalk.cyan.bold(`\n🧪 Generated ${harnesses.length} fuzzing harness(es)\n`));
      for (const h of manifest) {
        console.log(`  ${chalk.green(h.contract)}: ${h.invariants} invariants`);
        console.log(`    Echidna: ${chalk.gray(h.echidnaHarness)}`);
        console.log(`    Medusa:  ${chalk.gray(h.medusaHarness)}`);
      }
      console.log(chalk.yellow('\nRun: echidna <harness.sol> --config echidna.yaml'));
    } else {
      console.log(chalk.yellow('No contracts found to generate harnesses for.'));
    }
    console.log();
  });

program
  .command('symbolic')
  .description('Run symbolic execution: taint analysis, data-flow, path constraints')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or project directory')
  .action((opts) => {
    console.log(BANNER);
    const SymbolicExecutor = require('../lib/symbolic-executor');
    const Parser = require('../lib/parser');
    const parser = new Parser();
    const symbolic = new SymbolicExecutor();
    const stat = fs.statSync(opts.target);
    const results = stat.isDirectory() ? parser.parseProject(opts.target) : [parser.parseFile(opts.target)];
    const findings = symbolic.analyzeProject(results);
    console.log(chalk.cyan.bold(`\n🧬 Symbolic Execution Results: ${findings.length} finding(s)\n`));
    for (const f of findings) {
      const color = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue', info: 'gray' }[f.severity] || 'white';
      console.log(`  ${chalk[color].bold(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
      if (f.evidence) console.log(`  ${chalk.gray('Evidence:')} ${f.evidence}`);
    }
    console.log();
  });

program
  .command('invariant')
  .description('Check formal invariants: access control, accounting, reentrancy, overflow')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or project directory')
  .action((opts) => {
    console.log(BANNER);
    const InvariantChecker = require('../lib/invariant-checker');
    const Parser = require('../lib/parser');
    const parser = new Parser();
    const checker = new InvariantChecker();
    const stat = fs.statSync(opts.target);
    const results = stat.isDirectory() ? parser.parseProject(opts.target) : [parser.parseFile(opts.target)];
    const violations = checker.checkProject(results);
    console.log(chalk.cyan.bold(`\n📐 Invariant Check Results: ${violations.length} violation(s)\n`));
    for (const v of violations) {
      const color = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue', info: 'gray' }[v.severity] || 'white';
      console.log(`  ${chalk[color].bold(`[${v.severity.toUpperCase()}]`)} ${v.title}`);
      if (v.evidence) console.log(`  ${chalk.gray('Evidence:')} ${v.evidence}`);
    }
    console.log();
  });

program
  .command('cross-contract')
  .description('Analyze cross-contract interactions: reentrancy chains, composability, state deps')
  .requiredOption('-t, --target <path>', 'Path to Solidity project directory')
  .action((opts) => {
    console.log(BANNER);
    const CrossContractAnalyzer = require('../lib/cross-contract-analyzer');
    const Parser = require('../lib/parser');
    const parser = new Parser();
    const analyzer = new CrossContractAnalyzer();
    const results = parser.parseProject(opts.target);
    const findings = analyzer.analyze(results);
    console.log(chalk.cyan.bold(`\n🔗 Cross-Contract Analysis: ${findings.length} finding(s)\n`));
    for (const f of findings) {
      const color = { critical: 'red', high: 'red', medium: 'yellow', low: 'blue', info: 'gray' }[f.severity] || 'white';
      console.log(`  ${chalk[color].bold(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
      if (f.contracts) console.log(`  ${chalk.gray('Contracts:')} ${f.contracts.join(' → ')}`);
    }
    console.log();
  });

program.parse();
