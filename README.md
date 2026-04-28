# ⛓️ Codex Solidity — Smart Contract & Protocol Audit Agent

Impact-driven vulnerability discovery for Solidity smart contracts and DeFi protocols. Every finding includes **exploit contracts**, **attack flow**, and **financial impact calculations** proving real fund drain, pool freeze, and balance manipulation scenarios.

## 🚀 Quick Start

```bash
# Install dependencies
cd codex-solidity
npm install

# Audit a single contract
node bin/codex-sol.js audit -t ./contracts/Vault.sol

# Audit an entire project
node bin/codex-sol.js audit -t ./contracts/

# Run a single skill
node bin/codex-sol.js skill -t ./Vault.sol -n reentrancy

# Parse contract structure
node bin/codex-sol.js parse -t ./Vault.sol

# List available skills
node bin/codex-sol.js list

# Generate report from previous audit
node bin/codex-sol.js report -i ./audit-reports/audit-2026-04-28.json -f html
```

## 📋 Skills (33 Impact-Driven Modules)

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
│   ├── agent.js               # 3-phase orchestrator: parse → skills → report
│   ├── parser.js              # Solidity regex parser (contracts, functions, state vars, events)
│   ├── skill-loader.js        # Auto-discovers skills from /skills
│   ├── impact-engine.js       # Calculates drain amounts, generates exploit contracts
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
│   └── gas-griefing/index.js        # Gas DOS & external call in loop
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
```

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
