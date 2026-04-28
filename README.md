# ⛓️ Codex Solidity — Smart Contract & Protocol Audit Agent

Impact-driven vulnerability discovery for Solidity smart contracts and DeFi protocols. Every finding includes **exploit contracts**, **attack flow**, and **financial impact calculations** proving real fund drain, pool freeze, and balance manipulation scenarios.

## 🚀 Quick Start

```bash
# Install dependencies
cd codex-solidity
npm install

# Audit a local contract
node bin/codex-sol.js audit -t ./contracts/Vault.sol

# Audit a local project
node bin/codex-sol.js audit -t ./contracts/

# Audit a GitHub repo directly (just provide the link!)
node bin/codex-sol.js audit -t https://github.com/OpenZeppelin/openzeppelin-contracts

# Audit a GitHub subdirectory
node bin/codex-sol.js audit -t https://github.com/Aave/aave-v3-core/tree/main/contracts

# Audit with GPT-5.4 xhigh deep reasoning
node bin/codex-sol.js audit -t https://github.com/org/repo --llm --reasoning-effort xhigh

# Run a single skill
node bin/codex-sol.js skill -t ./Vault.sol -n reentrancy

# Parse contract structure
node bin/codex-sol.js parse -t ./Vault.sol

# List available skills
node bin/codex-sol.js list

# Generate report from previous audit
node bin/codex-sol.js report -i ./audit-reports/audit-2026-04-28.json -f html

# Query SWC Registry for known vulnerabilities
node bin/codex-sol.js mcp -q reentrancy -s swc

# Show agent configuration
node bin/codex-sol.js config
```

## 🐉 Kali Linux Setup

One-command setup on Kali Linux:

```bash
git clone https://github.com/noosi21/codex-solidity.git
cd codex-solidity
chmod +x setup-kali.sh
./setup-kali.sh
```

This installs:
- **Node.js 20.x** + npm
- **Foundry** (forge, cast, anvil) — for PoC compilation/testing
- **Slither** — Python static analyzer
- **Echidna** — property-based fuzzer
- **Codex Solidity** + all npm dependencies
- **OpenAI Codex CLI** (`codex` command) — GPT-5.4 xhigh agent
- **OpenAI API key** configuration (prompts for key)

## 🤖 Codex CLI Integration (GPT-5.4 xhigh Agent)

This project is designed to work **inside OpenAI Codex CLI** as an agentic audit workstation. The GPT-5.4 agent reads `AGENTS.md` for instructions and `.agents/skills/*/SKILL.md` for skill definitions, then executes our Node.js tools.

### Setup

```bash
# 1. Install Codex CLI
npm install -g @openai/codex

# 2. Login
codex login

# 3. Clone this repo
git clone https://github.com/noosi21/codex-solidity.git
cd codex-solidity
npm install

# 4. Start Codex CLI in the project directory
codex
```

### Interactive Bug Bounty Workflow

Once inside the Codex CLI REPL, just tell the agent what to audit:

```
> audit https://github.com/OpenZeppelin/openzeppelin-contracts

> run symbolic execution on the Vault contract

> check invariants on the Pool contract

> generate a fuzzing harness for the Token contract

> find reentrancy in all withdraw functions

> what are the cross-contract risks between Pool and Router?
```

The GPT-5.4 xhigh agent will:
1. Read `AGENTS.md` for audit persona + operational rules
2. Read `.agents/skills/audit-pro/SKILL.md` for the audit workflow
3. Execute `node bin/codex-sol.js audit -t <url>` to run the full pipeline
4. Review findings, validate them with deep reasoning
5. Write Foundry PoCs for confirmed vulnerabilities
6. Format findings in Sherlock/Immunefi bug bounty submission format

### One-Shot Mode

```bash
# Audit a repo in one command
codex "audit https://github.com/Aave/aave-v3-core for bug bounty" --model gpt-5.4-pro --reasoning-effort xhigh

# Focus on a specific vulnerability
codex "find reentrancy in https://github.com/org/repo" --model gpt-5.4-pro

# Generate PoC for a known issue
codex "write a Foundry PoC for the flash loan vulnerability in ./contracts/Vault.sol"
```

### How It Works

```
┌─────────────────────────────────────────────────┐
│              Codex CLI (GPT-5.4 xhigh)          │
│  Reads AGENTS.md → Gets audit persona + rules   │
│  Reads SKILL.md → Gets audit workflow steps     │
├─────────────────────────────────────────────────┤
│         Executes Node.js Tools via Shell         │
│  node bin/codex-sol.js audit -t <url>           │
│  node bin/codex-sol.js symbolic -t <path>       │
│  node bin/codex-sol.js invariant -t <path>      │
│  node bin/codex-sol.js cross-contract -t <path> │
│  node bin/codex-sol.js fuzz -t <path>           │
├─────────────────────────────────────────────────┤
│         GPT-5.4 xhigh Deep Reasoning            │
│  • Validates automated findings                  │
│  • Finds novel vulnerabilities static tools miss │
│  • Traces exploit paths step-by-step            │
│  • Quantifies financial impact                  │
│  • Generates Foundry PoCs                       │
│  • Formats bug bounty submissions               │
└─────────────────────────────────────────────────┘
```

### Standalone Mode (No Codex CLI)

You can also use the Node.js CLI directly — no Codex CLI needed:

```bash
# Full audit with built-in LLM reasoning
node bin/codex-sol.js audit -t https://github.com/org/repo --llm --reasoning-effort xhigh

# Or without LLM — pure static analysis
node bin/codex-sol.js audit -t ./contracts/
```

## 🤖 LLM Integration (GPT-5.4 xhigh)

### Setup

```bash
# Set your OpenAI API key
export OPENAI_API_KEY="sk-..."

# Or pass it inline
node bin/codex-sol.js audit -t ./contracts/ --llm --api-key "sk-..."
```

### What LLM Reasoning Adds

| Feature | Without LLM | With GPT-5.4 xhigh |
|---------|-------------|---------------------|
| Finding validation | Static rules only | LLM confirms true positives, dismisses false positives |
| False positive reduction | None | LLM reviews each critical/high finding |
| Audit synthesis | Raw findings list | Coherent narrative with attack trees + exploit paths |
| Cross-contract reasoning | Pattern matching | Deep logic analysis across contract interactions |
| Novel exploit detection | Known patterns only | LLM identifies novel vulnerability patterns |
| PoC generation | Template-based | LLM generates context-aware exploit contracts |

### Reasoning Effort Levels

| Level | Speed | Use Case |
|-------|-------|----------|
| `low` | ~5s/finding | Quick triage |
| `medium` | ~15s/finding | Standard audit |
| `high` | ~30s/finding | DeFi protocols (default) |
| `xhigh` | ~60s/finding | Complex multi-contract, novel exploits, $1M+ TVL |

### Example

```bash
# Full audit with maximum reasoning
node bin/codex-sol.js audit -t https://github.com/Aave/aave-v3-core \
  --llm \
  --llm-model gpt-5.4-pro \
  --reasoning-effort xhigh \
  --network mainnet
```

This produces:
1. **34 skills** → static findings
2. **Symbolic execution** → taint + data-flow findings
3. **Invariant checker** → formal invariant violations
4. **Cross-contract analyzer** → multi-file reentrancy chains
5. **LLM validation** → true positives confirmed, false positives dismissed
6. **LLM synthesis** → `llm-synthesis.md` with attack trees + recommendations
7. **Foundry PoCs** → runnable `.t.sol` exploit tests
8. **Fuzzing harnesses** → Echidna + Medusa configs

## 📋 Skills (34 Impact-Driven Modules)

### Core DeFi/Protocol Skills

| Skill | Severity | Impact Demonstration |
|-------|----------|---------------------|
| **reentrancy** | Critical | Full pool drain — attacker deposits 1 ETH, drains entire pool via recursive callback |
| **flash-loan** | Critical | Price manipulation in single tx — borrow 10K ETH, manipulate pool, drain via arbitrage |
| **access-control** | Critical | Unauthorized owner functions — anyone calls withdrawAll(), sweep(), mint() |
| **overflow** | Critical | Deposit 1 token, withdraw 2 → balance underflows to 2^256-1, drain everything |
| **pool-freeze** | High | Grow array past gas limit → ALL users permanently locked out, funds frozen forever |
| **oracle-manipulation** | High | Stale Chainlink, no TWAP → borrow against overvalued collateral, drain lending pool |
| **front-running** | High | No slippage protection → every swap sandwiched 5-30% loss, inflation attack |
| **delegatecall** | Critical | User-controlled delegatecall target → overwrite owner, full contract takeover |
| **self-destruct** | High | Force ETH via selfdestruct → break accounting, drain or freeze all funds |

### Trail of Bits Skills

| Skill | Severity | Impact Demonstration |
|-------|----------|---------------------|
| **unchecked-returns** | High | .call() return value ignored → silent failure, balance decremented but ETH not sent |
| **shadowing** | High | Child redeclares parent's `owner` → writes to different slot, parent owner stays 0x0 |
| **pragma-bugs** | High | Floating pragma → compiles with vulnerable compiler, storage corruption bugs |
| **signature-malleability** | High | ECDSA (r,s,v) and (r,n-s,v⊕1) both valid → double-spend via malleable signature |
| **erc20-assumptions** | High | Fee-on-transfer token: deposit 100, receive 90, credited 100 → insolvency |
| **timestamp-dependence** | Medium | block.timestamp manipulated by miners → lottery always won by miner |
| **storage-pointer** | High | Uninitialized storage var points to slot 0 → overwrites owner address |
| **inheritance-order** | High | C3 linearization: rightmost parent overrides → wrong function dispatched |
| **assembly-issues** | High | Hardcoded sstore(0, x) overwrites owner, extcodesize bypass, memory corruption |

### DeFi/Protocol Skills

| Skill | Severity | Impact Demonstration |
|-------|----------|---------------------|
| **erc4626-vault** | Critical | Inflation attack: donate ETH → inflate share price → victim gets 0 shares → total loss |
| **read-only-reentrancy** | Critical | View function returns stale data during callback → oracle reads wrong value → $100M+ losses |
| **rounding-errors** | High | Division before multiplication → precision loss → attacker extracts dust per tx |
| **liquidation-attack** | High | No grace period → MEV flash-loan liquidation → borrowers instantly liquidated |
| **proxy-upgrade** | Critical | Uninitialized implementation → anyone calls initialize() → contract takeover |
| **amm-math** | High | No k-invariant check → swap drains reserves without maintaining constant product |
| **reward-manipulation** | High | Stake/claim/unstake loop → drain rewards without time commitment |
| **bridge-vulnerability** | Critical | No message ID tracking → replay same message → drain bridge liquidity twice |
| **donation-attack** | High | Direct token transfer inflates share price → victim deposits, gets 0 shares |
| **eip-2612-permit** | High | No chain ID in domain → permit replay across L2s → tokens stolen on other chains |
| **nft-reentrancy** | High | onERC721Received callback re-enters during safeTransferFrom → bypasses ETH guards |
| **token-uri-manipulation** | Medium | SVG XSS in on-chain NFT → steals marketplace user cookies |
| **soulbound-bypass** | Medium | safeTransferFrom not blocked → "non-transferable" SBT actually transferable |
| **l2-sequencer** | High | Sequencer downtime → Chainlink freezes → borrow against stale price → drain pool |
| **gas-griefing** | Medium | External call in loop → grow array past gas limit → permanent DOS |
| **gas-optimization** | Low | Storage reads in loops → gas waste AND hidden logic flaw when loop modifies same variable |

## 🎯 Core Impact Scenarios

### 1. Fund Drain (Complete Pool Theft)
- **Reentrancy:** Deposit 1 ETH → recursive withdraw → drain entire pool
- **Overflow/Underflow:** Deposit 1, withdraw 2 → balance wraps to 2^256-1 → withdraw everything
- **Access Control:** Call unprotected withdrawAll() → steal all funds
- **Flash Loan:** Borrow 10K ETH → manipulate price → drain via arbitrage (zero risk, single tx)

### 2. User Pool Freeze (Permanent Fund Lock)
- **Unbounded Loop DOS:** Grow array past gas limit → withdraw() permanently fails
- **Push Payment DOS:** One reverting recipient blocks ALL payments
- **Force Feed:** selfdestruct ETH into contract → break balance invariant → all ops revert
- **Pause without Unpause:** pause() with no unpause() → funds locked forever

### 3. Attacker Steals More Than Deposited
- **Underflow:** balances[user] -= amount where amount > balance → wraps to 2^256-1
- **First-Depositor/Inflation:** Donate tokens before victim deposits → victim gets 0 shares
- **Oracle Manipulation:** Fake price → borrow more collateral than warranted
- **Address(this).balance:** Force ETH in → withdraw more than tracked deposits

## 🏗️ Architecture

```
codex-solidity/
├── bin/codex-sol.js           # CLI entry (commander)
├── lib/
│   ├── agent.js               # Orchestrator: parse → skills → correlate → PoC → report
│   ├── parser.js              # AST parser (@solidity-parser/parser) + regex fallback
│   ├── skill-loader.js        # Auto-discovers skills from /skills
│   ├── impact-engine.js       # Calculates drain amounts, generates exploit contracts
│   ├── mcp.js                 # MCP: SWC Registry + DeFiLlama intelligence
│   ├── foundry-poc.js         # Auto-generates Foundry .t.sol exploit test cases
│   ├── correlation-engine.js  # Cross-skill correlation: links combined exploit paths
│   ├── dynamic-severity.js    # Context-aware severity scoring (TVL, visibility, exploitability)
│   ├── external-tool-parser.js # Normalizes Slither/Aderyn/Mythril JSON into Codex format
│   ├── ci-integration.js      # CI mode, SARIF output, GitHub Actions workflow generator
│   ├── diff-auditor.js        # Git diff: only audit changed functions between refs
│   ├── interactive-mode.js    # REPL: drill into findings, re-score, generate PoCs
│   ├── symbolic-executor.js   # Symbolic execution: taint analysis, data-flow, path constraints
│   ├── fuzzing-engine.js      # Echidna + Medusa harness generator, invariant derivation
│   ├── invariant-checker.js   # Formal invariant verification (access, accounting, reentrancy)
│   ├── shared-state.js        # Cross-skill shared state: skills read each other's findings in real-time
│   ├── cross-contract-analyzer.js # Multi-file reentrancy chains, composability, state deps
│   ├── llm-reasoner.js       # GPT-5.4 xhigh: finding validation, audit synthesis, exploit PoC
│   ├── github-fetcher.js     # Fetch contracts from GitHub URLs (repo/tree/blob/raw)
│   └── report-generator.js    # HTML (dark) + Markdown + JSON reports
├── skills/
│   ├── reentrancy/index.js    # Reentrancy — recursive callback fund drain
│   ├── flash-loan/index.js    # Flash Loan — price manipulation, pool drain
│   ├── access-control/index.js # Access Control — unauthorized privileged functions
│   ├── overflow/index.js      # Integer Overflow/Underflow — balance wrapping
│   ├── pool-freeze/index.js   # Pool Freeze / DOS — permanent fund lock
│   ├── oracle-manipulation/index.js # Oracle — stale/fake price exploitation
│   ├── front-running/index.js # MEV — sandwich, slippage, inflation attack
│   ├── delegatecall/index.js  # Delegatecall — storage collision, proxy takeover
│   ├── self-destruct/index.js # Self-Destruct — force feed, accounting break
│   │
│   │  # Trail of Bits skills
│   ├── unchecked-returns/index.js  # Unchecked .call()/.send() return values
│   ├── shadowing/index.js          # State variable shadowing in inheritance
│   ├── pragma-bugs/index.js        # Floating pragma & known compiler bugs
│   ├── signature-malleability/index.js # ECDSA signature malleability & replay
│   ├── erc20-assumptions/index.js  # Fee-on-transfer, rebasing, non-standard tokens
│   ├── timestamp-dependence/index.js # block.timestamp manipulation
│   ├── storage-pointer/index.js    # Uninitialized storage pointers
│   ├── inheritance-order/index.js  # C3 linearization & missing super calls
│   └── assembly-issues/index.js    # Inline assembly vulnerabilities
│   │
│   │  # DeFi/Protocol skills
│   ├── erc4626-vault/index.js       # ERC4626 vault inflation/rounding attacks
│   ├── read-only-reentrancy/index.js # Read-only reentrancy via view functions
│   ├── rounding-errors/index.js     # Division-before-multiplication precision loss
│   ├── liquidation-attack/index.js  # Cascade liquidation & MEV front-running
│   ├── proxy-upgrade/index.js       # UUPS/Transparent proxy vulnerabilities
│   ├── amm-math/index.js            # AMM constant product invariant violations
│   ├── reward-manipulation/index.js # Staking reward gaming & double claims
│   ├── bridge-vulnerability/index.js # Cross-chain message replay & validator attacks
│   ├── donation-attack/index.js     # Direct transfer inflation attack
│   ├── eip-2612-permit/index.js     # Permit replay & signature validation
│   ├── nft-reentrancy/index.js      # ERC721/ERC1155 callback reentrancy
│   ├── token-uri-manipulation/index.js # SVG XSS & metadata manipulation
│   ├── soulbound-bypass/index.js   # SBT transfer restriction bypass
│   ├── l2-sequencer/index.js        # L2 sequencer downtime oracle freeze
│   ├── gas-griefing/index.js        # Gas DOS & external call in loop
│   └── gas-optimization/index.js    # Gas optimization reveals hidden logic flaws
├── .agents/skills/audit-pro/
│   ├── SKILL.md                  # Audit workflow: recon → analysis → PoC → report
│   ├── scripts/static_scan.sh    # Bridge to Slither/Aderyn/Codex
│   └── references/report_template.md  # Sherlock/Immunefi submission template
├── config.toml                  # Agent config: model, reasoning_effort, MCP servers
├── AGENTS.md                    # Durable auditor persona instructions
├── config/default.yaml
├── package.json
└── README.md
```

## ⚙️ CLI Options

```
audit  -t, --target <path>     Path to .sol file or directory (required)
       -s, --skills <list>     Comma-separated skills (default: all)
       -o, --output <dir>      Output directory (default: ./audit-reports)
       --compiler <version>    Solidity version (default: 0.8.19)
       --network <name>        Network context (default: mainnet)
       --exclude <list>        Paths to exclude
       --ci                    CI mode: non-zero exit if findings above threshold
       --fail-on <severity>    CI fail threshold: critical, high, medium (default: high)
       --diff <ref>            Diff mode: only audit changed functions (e.g. main...HEAD)
       --interactive           Interactive REPL: drill into findings after audit

mcp    -q, --query <query>     Search SWC Registry / DeFiLlama for known exploits
       -s, --source <source>   Source: swc, defillama, all (default: all)

diff   -b, --base <ref>        Base git ref (branch, commit, tag)
       -h, --head <ref>        Head git ref (default: working tree)

import -i, --input <path>     Import findings from Slither/Aderyn/Mythril JSON
       -t, --tool <name>       Tool: slither, aderyn, mythril, auto (default: auto)

ci-workflow                      Generate GitHub Actions workflow YAML

fuzz    -t, --target <path>     Generate Echidna + Medusa fuzzing harnesses
       -o, --output <dir>      Output directory for harnesses

symbolic -t, --target <path>    Run symbolic execution (taint + data-flow + path constraints)

invariant -t, --target <path>  Check formal invariants (access, accounting, reentrancy, overflow)

cross-contract -t, --target <path> Analyze cross-contract interactions (reentrancy chains, composability)

config                           Show current agent config (config.toml + AGENTS.md)
```

## 🧠 Agentic Audit Loop

### config.toml — The Engine
```toml
[model]
default = "gpt-5.4-pro"
reasoning_effort = "xhigh"       # Maximum thinking tokens for complex logic
max_completion_tokens = 100000

[features]
enable_subagents = true          # Parallel contract module analysis
enable_mcp = true                # External intelligence lookup
sandbox = "relaxed"              # Run local tests to verify PoCs

[audit]
auto_poc = true                  # Auto-generate PoC for every high/critical finding
submission_reports = true        # Sherlock/Immunefi format reports
```

### AGENTS.md — The Brain
Durable instructions that persist across sessions:
- **Auditor Persona**: Lead Security Researcher mindset, invariant-breaking focus
- **Operational Rules**: Static analysis first, PoC or it didn't happen, impact quantification
- **Attack Path Priority**: Fund drain → Pool freeze → Withdraw more than deposit → Privilege escalation → Cross-protocol impact
- **Severity Classification**: Based on quantified financial impact

### MCP — External Intelligence
- **SWC Registry**: Look up known Solidity vulnerability patterns (SWC-101 through SWC-138)
- **DeFiLlama**: Protocol TVL, exploit history, protocol-specific context
- Query: `node bin/codex-sol.js mcp -q reentrancy -s swc`

### .agents/skills/audit-pro/ — The Toolkit
- **SKILL.md**: 6-step audit workflow (Recon → Static Analysis → Deep Skill Analysis → PoC → Report → Gas Review)
- **scripts/static_scan.sh**: Bridges Codex with Slither, Aderyn, and custom patterns
- **references/report_template.md**: Sherlock/Immunefi submission-ready template

### 🆕 Engine Upgrades

| Module | What It Does |
|--------|-------------|
| **AST Parser** | Real AST via `@solidity-parser/parser` — catches nested calls, modifiers, inheritance that regex misses |
| **Foundry PoC Generator** | Auto-generates runnable `.t.sol` exploit tests for every critical/high finding |
| **Cross-Skill Correlation** | Detects combined exploits (e.g., read-only reentrancy + oracle = $100M+ class) |
| **Dynamic Severity** | Scores severity based on fund exposure, exploitability, access vector, state impact, cross-protocol reach |
| **External Tool Parser** | Imports Slither/Aderyn/Mythril JSON findings into unified Codex format |
| **CI/CD Integration** | `--ci` flag with exit codes, SARIF output, GitHub Actions workflow generator |
| **Diff Auditing** | `--diff main...HEAD` — only audits changed functions, skips untouched code |
| **Interactive Mode** | `--interactive` REPL: drill into findings, re-score, generate PoCs, query MCP |
| **Symbolic Execution** | Taint analysis: traces user input to dangerous sinks, data-flow: CEI violation detection, path constraints: bypassable guards |
| **Fuzzing Engine** | Auto-derives invariants from contract structure, generates Echidna + Medusa harnesses with 10+ invariant types |
| **Invariant Checker** | Certora-style formal verification: access control, accounting, reentrancy, overflow, state transition invariants |
| **Shared State** | Skills share context during execution — real-time cross-skill awareness instead of post-hoc correlation |
| **Cross-Contract Analyzer** | Multi-file reentrancy chains, callback reentrancy via ERC777/721 hooks, composability attacks, inheritance conflicts |

## 🔧 Adding Custom Skills

Create a directory under `skills/` with an `index.js`:

```js
module.exports = {
  name: 'my-skill',
  aliases: ['custom-check'],
  severity: 'high',
  description: 'My custom vulnerability check',
  async execute(ctx) {
    const { contracts, impactEngine, parser } = ctx;
    const findings = [];
    // Parse contracts, detect pattern, calculate impact
    return findings;
  },
};
```

Each finding: `title`, `severity`, `contract`, `function`, `evidence`, `impact`, `remediation`, `poc`.

## ⚠️ Legal Disclaimer

This tool is for **authorized security audits only**. Always obtain proper authorization before auditing any smart contract. Unauthorized testing may violate laws.

## 📄 License

MIT — Thabiso Noosi
