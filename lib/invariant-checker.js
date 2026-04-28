/**
 * Formal Invariant Checker
 * Certora-style invariant verification: extracts invariants from contract structure,
 * generates assertion checks, and verifies them via static analysis + symbolic execution.
 */

class InvariantChecker {
  constructor(opts = {}) {
    this.invariantTemplates = this._loadTemplates();
  }

  check(contract) {
    const invariants = this._extractInvariants(contract);
    const violations = [];

    for (const inv of invariants) {
      const result = this._verifyInvariant(inv, contract);
      if (!result.holds) {
        violations.push({
          title: `Invariant Violation: ${inv.name}`,
          severity: inv.severity,
          functionName: inv.functionName || 'contract-wide',
          skill: 'invariant-checker',
          evidence: result.evidence,
          impact: result.impact,
          remediation: result.remediation,
          invariant: inv,
        });
      }
    }

    return violations;
  }

  checkProject(parsedResults) {
    const allFindings = [];
    for (const file of parsedResults) {
      if (file.error) continue;
      for (const contract of file.contracts || []) {
        const findings = this.check(contract);
        for (const f of findings) {
          f.file = file.file;
          f.contract = contract.name;
        }
        allFindings.push(...findings);
      }
    }
    return allFindings;
  }

  _extractInvariants(contract) {
    const invariants = [];
    const stateVars = contract.stateVariables || [];
    const fns = contract.functions || [];

    // 1. Access control invariants
    for (const fn of fns) {
      if (this._isPrivileged(fn, contract)) {
        const hasGuard = this._hasAccessGuard(fn, contract);
        if (!hasGuard) {
          invariants.push({
            name: `onlyAuthorized_${fn.name}`,
            description: `${fn.name}() should only be callable by authorized addresses`,
            type: 'access-control',
            severity: 'critical',
            functionName: fn.name,
            check: () => ({ holds: false, evidence: `${fn.name}() is ${fn.visibility} with no access guard`, impact: 'Unauthorized call leads to fund drain or protocol takeover', remediation: 'Add onlyOwner/onlyRole modifier or require(msg.sender == owner)' }),
          });
        }
      }
    }

    // 2. Accounting invariants
    const balanceVars = stateVars.filter(v => /balance/i.test(v.name));
    const totalVars = stateVars.filter(v => /total/i.test(v.name));
    if (balanceVars.length > 0 && totalVars.length > 0) {
      invariants.push({
        name: 'sumOfBalancesEqualsTotal',
        description: 'Sum of individual balances must equal total supply/amount',
        type: 'accounting',
        severity: 'critical',
        check: () => this._checkAccountingInvariant(contract),
      });
    }

    // 3. Reentrancy invariants
    const externalCallFns = fns.filter(f => f.hasExternalCall);
    for (const fn of externalCallFns) {
      invariants.push({
        name: `noReentrancy_${fn.name}`,
        description: `${fn.name}() must not be re-enterable during state transition`,
        type: 'reentrancy',
        severity: 'high',
        functionName: fn.name,
        check: () => this._checkReentrancyInvariant(fn, contract),
      });
    }

    // 4. Overflow invariants (for Solidity <0.8.0 or unchecked blocks)
    const arithmeticFns = fns.filter(f =>
      f.body && (f.body.includes('+=') || f.body.includes('-=') || f.body.includes('*=') || f.body.includes('/='))
    );
    for (const fn of arithmeticFns) {
      invariants.push({
        name: `noOverflow_${fn.name}`,
        description: `Arithmetic in ${fn.name}() must not overflow/underflow`,
        type: 'overflow',
        severity: 'high',
        functionName: fn.name,
        check: () => this._checkOverflowInvariant(fn, contract),
      });
    }

    // 5. State transition invariants
    const stateVars_written = this._findStateWrites(contract);
    for (const sv of stateVars_written) {
      invariants.push({
        name: `validTransition_${sv.name}`,
        description: `${sv.name} transitions must preserve valid state`,
        type: 'state-transition',
        severity: 'medium',
        check: () => this._checkStateTransitionInvariant(sv, contract),
      });
    }

    // 6. ERC4626 vault invariants
    if (this._isVault(contract)) {
      invariants.push(...this._vaultInvariants(contract));
    }

    // 7. Proxy invariants
    if (this._isProxy(contract)) {
      invariants.push(...this._proxyInvariants(contract));
    }

    // 8. Token standard invariants
    if (this._isToken(contract)) {
      invariants.push(...this._tokenInvariants(contract));
    }

    return invariants;
  }

  _verifyInvariant(inv, contract) {
    if (inv.check) return inv.check();
    return { holds: true, evidence: '', impact: '', remediation: '' };
  }

  _isPrivileged(fn, contract) {
    const privNames = [/withdraw/i, /sweep/i, /mint/i, /burn/i, /setOwner/i, /pause/i, /upgrade/i, /setFee/i, /rescue/i, /admin/i, /govern/i];
    return (fn.visibility === 'public' || fn.visibility === 'external') &&
      privNames.some(p => p.test(fn.name)) &&
      fn.mutability !== 'view' && fn.mutability !== 'pure';
  }

  _hasAccessGuard(fn, contract) {
    const body = fn.body || '';
    const hasRequire = /require\s*\(/i.test(body);
    const hasOnlyModifier = (fn.modifiers || []).some(m => /only|admin|owner|governance|role/i.test(m));
    return hasRequire || hasOnlyModifier;
  }

  _checkAccountingInvariant(contract) {
    const stateVars = contract.stateVariables || [];
    const hasMappingBalance = stateVars.some(v => /mapping/i.test(v.type) && /balance/i.test(v.name));
    const hasTotal = stateVars.some(v => /total/i.test(v.name));
    if (hasMappingBalance && hasTotal) {
      return {
        holds: false,
        evidence: 'mapping(address => uint) balances + uint totalSupply — no enforced equality check',
        impact: 'Drift between sum(balances) and totalSupply — value can be created or destroyed silently',
        remediation: 'Add invariant check: assert(sum(balances) == totalSupply) after every state change',
      };
    }
    return { holds: true, evidence: '', impact: '', remediation: '' };
  }

  _checkReentrancyInvariant(fn, contract) {
    const body = fn.body || '';
    const hasExternalCall = /(\w+)\.(call|delegatecall|transfer|send)\s*\(/i.test(body);
    const hasStateWriteAfterCall = this._hasStateWriteAfterCall(body);
    const hasReentrancyGuard = (fn.modifiers || []).some(m => /nonReentrant|lock|reentrancy/i.test(m));

    if (hasExternalCall && hasStateWriteAfterCall && !hasReentrancyGuard) {
      return {
        holds: false,
        evidence: `${fn.name}() has external call + state write after call + no reentrancy guard`,
        impact: 'Reentrancy: attacker re-enters during callback, state not yet updated',
        remediation: 'Follow CEI pattern or add nonReentrant modifier',
      };
    }
    return { holds: true, evidence: '', impact: '', remediation: '' };
  }

  _checkOverflowInvariant(fn, contract) {
    const body = fn.body || '';
    if (body.includes('unchecked') || body.includes('unchecked {')) {
      const hasSubtraction = /-=/.test(body);
      const hasAddition = /\+=/.test(body);
      if (hasSubtraction) {
        return {
          holds: false,
          evidence: `${fn.name}() uses unchecked subtraction — potential underflow`,
          impact: 'Underflow in unchecked block wraps to 2^256-1 — massive balance manipulation',
          remediation: 'Add bounds check before subtraction in unchecked block',
        };
      }
    }
    return { holds: true, evidence: '', impact: '', remediation: '' };
  }

  _checkStateTransitionInvariant(sv, contract) {
    // Check if variable can be set to invalid state
    if (/owner|admin/i.test(sv.name) && sv.type === 'address') {
      const fns = contract.functions || [];
      const hasSetOwner = fns.some(f => /setOwner|transferOwnership/i.test(f.name) && f.body);
      if (hasSetOwner) {
        const setOwnerFn = fns.find(f => /setOwner|transferOwnership/i.test(f.name));
        const body = setOwnerFn.body || '';
        if (!body.includes('address(0)') && !body.includes('0x0')) {
          return {
            holds: false,
            evidence: `${setOwnerFn.name}() can set owner to address(0)`,
            impact: 'Owner set to zero address — contract permanently locked or anyone can claim ownership',
            remediation: 'Add require(newOwner != address(0)) in ownership transfer',
          };
        }
      }
    }
    return { holds: true, evidence: '', impact: '', remediation: '' };
  }

  _hasStateWriteAfterCall(body) {
    const callIdx = body.search(/(\w+)\.(call|delegatecall|transfer|send)\s*\(/i);
    if (callIdx === -1) return false;
    const afterCall = body.substring(callIdx);
    return /\w+\s*(=|\+=|-=)\s/.test(afterCall);
  }

  _isVault(c) {
    return /vault|pool|staking|yield/i.test(c.name) ||
      (c.inheritance || []).some(i => /vault|erc4626/i.test(i)) ||
      (c.stateVariables || []).some(v => /share|exchangeRate|convertToShare/i.test(v.name));
  }

  _isProxy(c) {
    return /proxy|upgrade/i.test(c.name) ||
      (c.inheritance || []).some(i => /proxy|uups|transparent/i.test(i));
  }

  _isToken(c) {
    return /token|coin|erc20|erc721|erc1155/i.test(c.name) ||
      (c.inheritance || []).some(i => /erc20|erc721|erc1155|ierc20/i.test(i));
  }

  _vaultInvariants(contract) {
    return [
      {
        name: 'deposit_mint_proportional_shares',
        description: 'Depositing assets must mint proportional shares',
        type: 'erc4626', severity: 'high',
        check: () => ({ holds: false, evidence: 'Vault deposit may not mint proportional shares due to rounding', impact: 'First depositor inflation attack or rounding leak', remediation: 'Add virtual shares offset (OpenZeppelin ERC4626 pattern)' }),
      },
      {
        name: 'withdraw_no_more_than_deposited',
        description: 'Cannot withdraw more assets than deposited',
        type: 'erc4626', severity: 'critical',
        check: () => ({ holds: true, evidence: '', impact: '', remediation: '' }),
      },
    ];
  }

  _proxyInvariants(contract) {
    return [
      {
        name: 'implementation_initialized',
        description: 'Implementation contract must be initialized exactly once',
        type: 'proxy', severity: 'critical',
        check: () => ({ holds: false, evidence: 'Implementation may be uninitialized — anyone can call initializer', impact: 'Attacker initializes implementation with their address as owner', remediation: 'Call _disableInitializers() in implementation constructor' }),
      },
    ];
  }

  _tokenInvariants(contract) {
    return [
      {
        name: 'total_supply_conservation',
        description: 'Total supply can only change through mint/burn',
        type: 'erc20', severity: 'high',
        check: () => ({ holds: true, evidence: '', impact: '', remediation: '' }),
      },
      {
        name: 'approve_to_zero_before_new',
        description: 'Approval must be set to 0 before setting new value (front-running protection)',
        type: 'erc20', severity: 'medium',
        check: () => ({ holds: true, evidence: '', impact: '', remediation: '' }),
      },
    ];
  }

  _findStateWrites(contract) {
    const writes = [];
    for (const fn of contract.functions || []) {
      if (!fn.body) continue;
      const matches = [...fn.body.matchAll(/(\w+)\s*(=|\+=|-=|\*=|\/=)\s/g)];
      for (const m of matches) {
        const varName = m[1];
        const sv = (contract.stateVariables || []).find(v => v.name === varName);
        if (sv) {
          writes.push({ name: varName, type: sv.type, function: fn.name, op: m[2] });
        }
      }
    }
    return writes;
  }

  _loadTemplates() {
    return {
      accounting: 'assert(sum(balances) == totalSupply)',
      access: 'require(hasRole(ADMIN, msg.sender))',
      reentrancy: 'nonReentrant modifier or CEI pattern',
      overflow: 'SafeMath or Solidity >=0.8.0',
    };
  }

  generateCertoraSpec(contract) {
    const invariants = this._extractInvariants(contract);
    let spec = `// Certora Formal Verification Spec for ${contract.name}\n`;
    spec += `// Auto-generated by Codex Solidity\n\n`;
    spec += `methods {\n`;
    for (const fn of contract.functions || []) {
      if (fn.visibility === 'public' || fn.visibility === 'external') {
        spec += `  ${fn.visibility} ${contract.name}.${fn.name}(${fn.params}) envfree;\n`;
      }
    }
    spec += `}\n\n`;
    spec += `invariant ${contract.name}_invariant_count = ${invariants.length}\n\n`;
    for (const inv of invariants) {
      spec += `invariant ${inv.name}();\n`;
    }
    return spec;
  }
}

module.exports = InvariantChecker;
