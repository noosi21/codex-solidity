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

program.parse();
