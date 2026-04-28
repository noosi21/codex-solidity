---
name: protocol-audit
description: Triggers deep auditing of smart contracts (Solidity/Move) with invariant-breaking focus.
---

# Security Audit Workflow

## Step 1: Reconnaissance
- Parse all contracts, list public/external functions, identify privileged roles.
- Map state variables, modifiers, events, and inheritance chains.
- Identify the attack surface: payable functions, external calls, delegatecalls, assembly blocks.
- Check pragma version and compiler settings.

## Step 2: Static Analysis
- Run `./scripts/static_scan.sh` for automated pattern detection.
- Analyze Slither/Aderyn output for known vulnerability patterns.
- Cross-reference with SWC Registry for known weaknesses.

## Step 3: Deep Skill Analysis
- Execute all enabled skills against parsed contracts.
- For each skill finding, validate with invariant checks:
  - Is `totalSupply == sum(balances)` broken?
  - Is `contract_balance >= total_deposits - total_withdrawals` broken?
  - Is `only_owner_can_call_restricted_functions` broken?
  - Is `shares_are_always_backed_by_assets` broken?
- Prioritize invariant-breaking findings as Critical.

## Step 4: Proof of Concept
- For every High/Critical finding, generate a failing test case.
- PoC must demonstrate: (1) initial state, (2) attacker action, (3) broken invariant, (4) financial impact.
- If PoC fails to compile, debug the test environment first.
- Use Foundry test format for Solidity PoCs.

## Step 5: Report Generation
- Generate report in Sherlock/Immunefi format.
- Include: Title, Severity, Description, Impact, Proof of Concept, Recommended Mitigation.
- Quantify financial impact: "Attacker drains X ETH from pool of Y ETH."
- Auto-fill submission template from `references/report_template.md`.

## Step 6: Gas/Compute Optimization Review
- Analyze gas-intensive patterns that may indicate hidden logic flaws.
- Check for: unnecessary storage reads, redundant computations, unbounded loops.
- Optimization findings may reveal security issues (e.g., gas griefing vectors).

## Triggers
- Automatically starts when `.sol` files are detected in the target directory.
- Can be manually triggered with: `codex-sol audit -t <path>`
