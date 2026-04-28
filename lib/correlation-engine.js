/**
 * Cross-Skill Correlation Engine
 * Links findings across skills to detect combined exploits.
 * E.g., read-only reentrancy + oracle manipulation = critical combined attack
 */

class CorrelationEngine {
  constructor() {
    this.rules = [
      {
        name: 'Reentrancy + Access Control Bypass',
        skills: ['reentrancy', 'access-control'],
        severity: 'critical',
        pattern: 'External call followed by state change in unprotected function — attacker re-enters during callback and bypasses access control before state update',
        combinedImpact: 'Full contract drain via reentrancy in unprotected function — no access control means anyone can trigger the exploit path',
      },
      {
        name: 'Read-Only Reentrancy + Oracle Manipulation',
        skills: ['read-only-reentrancy', 'oracle-manipulation'],
        severity: 'critical',
        pattern: 'View function returns stale data during callback — oracle reads this stale value — attacker manipulates oracle price via reentrancy',
        combinedImpact: '$100M+ class exploit — manipulate oracle price during reentrancy callback, borrow against inflated collateral, drain lending pool',
      },
      {
        name: 'ERC4626 Inflation + Donation Attack',
        skills: ['erc4626-vault', 'donation-attack'],
        severity: 'critical',
        pattern: 'Direct token donation inflates share price in ERC4626 vault — victim deposits and receives 0 shares — attacker holds all shares',
        combinedImpact: 'Victim loses 100% of deposit — attacker controls entire vault via share price inflation',
      },
      {
        name: 'Flash Loan + Oracle Manipulation',
        skills: ['flash-loan', 'oracle-manipulation'],
        severity: 'critical',
        pattern: 'Flash loan provides capital to manipulate oracle price in single transaction — no risk to attacker',
        combinedImpact: 'Zero-risk pool drain — borrow flash loan, manipulate price oracle, exploit price difference, repay loan, keep profit',
      },
      {
        name: 'Proxy Upgrade + Delegatecall Injection',
        skills: ['proxy-upgrade', 'delegatecall'],
        severity: 'critical',
        pattern: 'Unprotected UUPS upgrade function + delegatecall to attacker-controlled logic — full contract takeover',
        combinedImpact: 'Complete protocol takeover — attacker upgrades implementation to malicious contract, drains all funds',
      },
      {
        name: 'Bridge + Reentrancy',
        skills: ['bridge-vulnerability', 'reentrancy'],
        severity: 'critical',
        pattern: 'Cross-chain message callback enables reentrancy — replay messages during callback — drain bridge liquidity multiple times',
        combinedImpact: 'Bridge drain multiplied by reentrancy depth — each callback replays withdrawal, draining bridge N times',
      },
      {
        name: 'Rounding Errors + ERC4626 Vault',
        skills: ['rounding-errors', 'erc4626-vault'],
        severity: 'high',
        pattern: 'Share conversion rounds down in vault — attacker extracts dust per transaction — scales across pool over time',
        combinedImpact: 'Slow drain of vault assets — rounding error compounds with inflation attack to steal more than expected',
      },
      {
        name: 'Liquidation + Oracle Manipulation',
        skills: ['liquidation-attack', 'oracle-manipulation'],
        severity: 'critical',
        pattern: 'Oracle manipulation makes healthy positions appear underwater — instant liquidation — MEV front-runs liquidators',
        combinedImpact: 'Cascade liquidations drain borrower collateral — oracle manipulation triggers mass liquidations, MEV extracts value',
      },
      {
        name: 'L2 Sequencer + Oracle Freeze',
        skills: ['l2-sequencer', 'oracle-manipulation'],
        severity: 'high',
        pattern: 'Sequencer downtime freezes Chainlink oracle — stale price used for lending/borrowing — attacker exploits stale price',
        combinedImpact: 'Borrow against stale (overvalued) collateral during sequencer downtime — drain lending pool when sequencer resumes',
      },
      {
        name: 'Gas Griefing + Pool Freeze',
        skills: ['gas-griefing', 'pool-freeze'],
        severity: 'high',
        pattern: 'External call in unbounded loop + gas griefing — grow array past gas limit — permanent DOS on withdrawals',
        combinedImpact: 'Permanent fund lock — gas griefing amplifies pool freeze, all users unable to withdraw forever',
      },
      {
        name: 'Unchecked Returns + Reentrancy',
        skills: ['unchecked-returns', 'reentrancy'],
        severity: 'high',
        pattern: 'External call return value ignored + reentrancy possible — silent failure masks the reentrancy vector',
        combinedImpact: 'Reentrancy exploit goes undetected because return value check is missing — funds silently drained',
      },
      {
        name: 'NFT Reentrancy + ERC4626 Vault',
        skills: ['nft-reentrancy', 'erc4626-vault'],
        severity: 'high',
        pattern: 'onERC721Received callback re-enters vault deposit/withdraw — bypasses share calculation — inflates or deflates shares',
        combinedImpact: 'Vault share manipulation via NFT callback reentrancy — attacker gains more shares than entitled',
      },
    ];
  }

  correlate(findings) {
    const correlations = [];
    const skillFindings = {};

    // Group findings by skill
    for (const f of findings) {
      const skill = f.skill || 'unknown';
      if (!skillFindings[skill]) skillFindings[skill] = [];
      skillFindings[skill].push(f);
    }

    // Check each correlation rule
    for (const rule of this.rules) {
      const matchingSkills = rule.skills.filter(s => skillFindings[s]);
      if (matchingSkills.length >= 2) {
        // Both skills have findings — correlated vulnerability
        const relatedFindings = rule.skills.flatMap(s => skillFindings[s] || []);
        correlations.push({
          name: rule.name,
          severity: rule.severity,
          pattern: rule.pattern,
          combinedImpact: rule.combinedImpact,
          skills: matchingSkills,
          findings: relatedFindings,
          recommendation: this._recommendation(rule),
        });
      }
    }

    return correlations;
  }

  _recommendation(rule) {
    const recs = {
      'Reentrancy + Access Control Bypass': 'Add reentrancy guard AND access control to all state-changing external functions',
      'Read-Only Reentrancy + Oracle Manipulation': 'Use TWAP oracle with reentrancy guards on view functions that feed oracles',
      'ERC4626 Inflation + Donation Attack': 'Add virtual shares offset, minimum deposit, and block direct token transfers',
      'Flash Loan + Oracle Manipulation': 'Use TWAP oracle over multiple blocks, add price deviation bounds',
      'Proxy Upgrade + Delegatecall Injection': 'Add access control on upgrade function, initialize implementation in constructor',
      'Bridge + Reentrancy': 'Add message ID tracking, process messages atomically, add reentrancy guard',
      'Rounding Errors + ERC4626 Vault': 'Multiply before divide, add rounding direction favors vault, minimum share threshold',
      'Liquidation + Oracle Manipulation': 'Add grace period, TWAP oracle, liquidation incentive cap, circuit breaker',
      'L2 Sequencer + Oracle Freeze': 'Add sequencer uptime check, grace period after downtime, fallback oracle',
      'Gas Griefing + Pool Freeze': 'Bound loops, use pull payments, add gas estimation checks',
      'Unchecked Returns + Reentrancy': 'Check all .call() return values, add reentrancy guard',
      'NFT Reentrancy + ERC4626 Vault': 'Add reentrancy guard to NFT callback handlers, check vault state after callback',
    };
    return recs[rule.name] || 'Review both findings and implement combined mitigation';
  }
}

module.exports = CorrelationEngine;
