/**
 * Symbolic Execution Engine
 * Data-flow analysis, taint tracking, and path constraint solver.
 * Traces how user-controlled data flows through contract to dangerous sinks.
 */

class SymbolicExecutor {
  constructor(opts = {}) {
    this.sinks = [
      { pattern: /\.call\(/, type: 'external-call', severity: 'high' },
      { pattern: /\.delegatecall\(/, type: 'delegatecall', severity: 'critical' },
      { pattern: /selfdestruct/, type: 'selfdestruct', severity: 'critical' },
      { pattern: /\.transfer\(/, type: 'transfer', severity: 'medium' },
      { pattern: /\.send\(/, type: 'send', severity: 'medium' },
      { pattern: /require\s*\(/, type: 'require-bypass', severity: 'high' },
      { pattern: /tx\.origin/, type: 'tx-origin', severity: 'high' },
      { pattern: /assembly/, type: 'assembly', severity: 'high' },
    ];
    this.sources = ['msg.sender', 'msg.value', 'msg.data', 'tx.origin', 'block.timestamp', 'block.number', 'externally controlled'];
  }

  analyze(contract) {
    const findings = [];
    const functions = contract.functions || [];

    for (const fn of functions) {
      if (!fn.body) continue;

      // 1. Taint analysis: trace user input to dangerous sinks
      const taintFindings = this._taintAnalysis(fn, contract);
      findings.push(...taintFindings);

      // 2. Data-flow: track state variable writes after external calls
      const dataFlowFindings = this._dataFlowAnalysis(fn, contract);
      findings.push(...dataFlowFindings);

      // 3. Path constraints: check if guards are bypassable
      const pathFindings = this._pathConstraintAnalysis(fn, contract);
      findings.push(...pathFindings);
    }

    return findings;
  }

  analyzeProject(parsedResults) {
    const allFindings = [];
    for (const file of parsedResults) {
      if (file.error) continue;
      for (const contract of file.contracts || []) {
        const findings = this.analyze(contract);
        for (const f of findings) {
          f.file = file.file;
          f.contract = contract.name;
        }
        allFindings.push(...findings);
      }
    }
    return allFindings;
  }

  _taintAnalysis(fn, contract) {
    const findings = [];
    const body = fn.body || '';
    const params = (fn.params || '').split(',').map(p => p.trim().split(' ').pop()).filter(Boolean);

    // Check if function parameters or msg.* flow to sinks without validation
    for (const sink of this.sinks) {
      if (!sink.pattern.test(body)) continue;

      // Find taint sources that reach this sink
      const taintSources = [];
      for (const src of this.sources) {
        if (body.includes(src)) taintSources.push(src);
      }
      // Function params are also taint sources
      for (const param of params) {
        if (param && body.includes(param)) taintSources.push(param);
      }

      if (taintSources.length > 0) {
        // Check if there's a guard between source and sink
        const hasGuard = /require\s*\(/.test(body) || /if\s*\(/.test(body);
        const guardQuality = this._assessGuardQuality(body, sink.type);

        if (guardQuality === 'weak' || guardQuality === 'none') {
          findings.push({
            title: `Symbolic: Tainted ${taintSources[0]} reaches ${sink.type} in ${fn.name}()`,
            severity: sink.severity,
            functionName: fn.name,
            skill: 'symbolic-execution',
            evidence: `Source: ${taintSources.join(', ')} -> Sink: ${sink.type}. Guard quality: ${guardQuality}`,
            impact: `User-controlled ${taintSources[0]} flows to ${sink.type} without adequate validation — potential ${sink.type} exploit`,
            remediation: this._remediate(sink.type, taintSources[0]),
          });
        }
      }
    }
    return findings;
  }

  _dataFlowAnalysis(fn, contract) {
    const findings = [];
    const body = fn.body || '';

    // Pattern: external call followed by state write (CEI violation)
    const externalCallPattern = /(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*\(/g;
    const stateWritePattern = /\b(\w+)\s*(=|\+=|-=|\*=|\/=)\s/g;

    let callMatch;
    const calls = [];
    while ((callMatch = externalCallPattern.exec(body)) !== null) {
      calls.push({ target: callMatch[1], method: callMatch[2], index: callMatch.index });
    }

    let writeMatch;
    const writes = [];
    while ((writeMatch = stateWritePattern.exec(body)) !== null) {
      writes.push({ var: writeMatch[1], op: writeMatch[2], index: writeMatch.index });
    }

    // Check if any state write happens AFTER an external call (CEI violation)
    for (const call of calls) {
      for (const write of writes) {
        if (write.index > call.index && !/^(return|emit|require|assert|revert|local|memory|calldata)/.test(write.var)) {
          // Check if the variable is a storage variable
          const isStorage = (contract.stateVariables || []).some(v => v.name === write.var);
          if (isStorage) {
            findings.push({
              title: `Symbolic: State write after external call in ${fn.name}() — CEI violation`,
              severity: 'high',
              functionName: fn.name,
              skill: 'symbolic-execution',
              evidence: `${call.target}.${call.method}() at pos ${call.index} -> ${write.var}${write.op} at pos ${write.index}`,
              impact: `State variable ${write.var} modified after external call to ${call.target} — reentrancy vector`,
              remediation: `Follow Checks-Effects-Interactions: move ${write.var} write before ${call.target}.${call.method}()`,
            });
          }
        }
      }
    }

    // Pattern: return value of external call ignored
    if (/\.call\s*\(/g.test(body) && !/\.call\s*\(\{[^}]*\}\)/.test(body)) {
      const callResults = body.match(/(\w+)\.call\s*\(/g) || [];
      for (const cr of callResults) {
        const varName = cr.match(/(\w+)\.call/)[1];
        // Check if result is captured
        const resultCapture = new RegExp(`\\(.*success.*\\)\\s*=?\\s*${varName}\\.call|${varName}\\.call.*=>|bool\\s+\\w+\\s*=\\s*${varName}\\.call`);
        if (!resultCapture.test(body) && !body.includes('require(' + varName) && !body.includes('if (' + varName) && !body.includes('!')) {
          findings.push({
            title: `Symbolic: Unchecked .call() return value in ${fn.name}()`,
            severity: 'high',
            functionName: fn.name,
            skill: 'symbolic-execution',
            evidence: `${varName}.call() return value not checked`,
            impact: 'Silent failure — ETH not sent but balance decremented, or delegatecall fails silently',
            remediation: `Check return value: (bool success, ) = ${varName}.call{value: amount}(""); require(success);`,
          });
        }
      }
    }

    return findings;
  }

  _pathConstraintAnalysis(fn, contract) {
    const findings = [];
    const body = fn.body || '';

    // Check for bypassable access controls
    const requirePattern = /require\s*\(\s*([^,)]+)/g;
    let reqMatch;
    while ((reqMatch = requirePattern.exec(body)) !== null) {
      const condition = reqMatch[1].trim();

      // Weak guards
      if (condition.includes('msg.sender != address(0)') || condition.includes('msg.sender != 0x0')) {
        findings.push({
          title: `Symbolic: Trivial access control in ${fn.name}() — only checks non-zero address`,
          severity: 'high',
          functionName: fn.name,
          skill: 'symbolic-execution',
          evidence: `require(${condition}) — any non-zero address passes`,
          impact: 'Any address can call this function — not real access control',
          remediation: 'Use proper role-based access: require(hasRole(ADMIN_ROLE, msg.sender))',
        });
      }

      // tx.origin in require — phishing bypass
      if (condition.includes('tx.origin')) {
        findings.push({
          title: `Symbolic: tx.origin used for auth in ${fn.name}() — phishing bypass`,
          severity: 'high',
          functionName: fn.name,
          skill: 'symbolic-execution',
          evidence: `require(${condition}) — tx.origin is phishing-vulnerable`,
          impact: 'Attacker tricks victim into calling attacker contract, which calls this function — tx.origin passes check',
          remediation: 'Use msg.sender instead of tx.origin for authentication',
        });
      }
    }

    // Check for missing access control on privileged functions
    const privilegedPatterns = [/withdraw/i, /sweep/i, /mint/i, /burn/i, /setOwner/i, /pause/i, /upgrade/i, /setFee/i];
    const hasAnyGuard = /require\s*\(/.test(body) || /onlyOwner|onlyAdmin|onlyRole|onlyGovernance/.test(body) ||
      (fn.modifiers || []).some(m => /only|admin|owner|governance/i.test(m));

    if (!hasAnyGuard && fn.visibility !== 'private' && fn.visibility !== 'internal') {
      for (const pat of privilegedPatterns) {
        if (pat.test(fn.name)) {
          findings.push({
            title: `Symbolic: No access control on privileged function ${fn.name}()`,
            severity: 'critical',
            functionName: fn.name,
            skill: 'symbolic-execution',
            evidence: `${fn.name}() is ${fn.visibility} with no require/modifier guard`,
            impact: `Anyone can call ${fn.name}() — potential fund drain or protocol takeover`,
            remediation: `Add access control: require(msg.sender == owner) or onlyOwner modifier`,
          });
          break;
        }
      }
    }

    return findings;
  }

  _assessGuardQuality(body, sinkType) {
    const requires = [...body.matchAll(/require\s*\(\s*([^)]+)\)/g)].map(m => m[1]);

    if (requires.length === 0) return 'none';

    for (const req of requires) {
      // Strong guards: role checks, owner checks
      if (/owner|admin|role|governance|multisig/i.test(req)) return 'strong';
      // Medium guards: balance checks, amount limits
      if (/balance|amount|limit/i.test(req)) return 'medium';
      // Weak guards: non-zero checks, simple comparisons
      if (/address\(0\)|0x0|!=\s*0|>\s*0/i.test(req)) return 'weak';
    }

    return 'medium';
  }

  _remediate(sinkType, source) {
    const recs = {
      'external-call': `Validate ${source} before external call, use reentrancy guard, follow CEI pattern`,
      'delegatecall': `Restrict delegatecall target to trusted addresses, validate ${source}`,
      'selfdestruct': `Remove selfdestruct or add strict access control on ${source}`,
      'transfer': `Use push-pull pattern, validate ${source} before transfer`,
      'send': `Check send() return value, use .call() instead`,
      'require-bypass': `Strengthen require condition, use role-based access instead of simple checks`,
      'tx-origin': `Replace tx.origin with msg.sender for authentication`,
      'assembly': `Validate assembly inputs, avoid hardcoded storage slots`,
    };
    return recs[sinkType] || `Add proper validation for ${source} before reaching ${sinkType}`;
  }
}

module.exports = SymbolicExecutor;
