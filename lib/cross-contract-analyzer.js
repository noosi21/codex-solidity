/**
 * Cross-Contract Analysis
 * Detects multi-file reentrancy chains, cross-contract state dependencies,
 * and protocol-level vulnerabilities that single-contract analysis misses.
 */

class CrossContractAnalyzer {
  constructor(opts = {}) {
    this.sharedState = opts.sharedState || null;
  }

  analyze(parsedResults) {
    const findings = [];

    // Build contract registry
    const registry = this._buildRegistry(parsedResults);

    // 1. Cross-contract reentrancy chains
    const reentrancyChains = this._findReentrancyChains(registry);
    findings.push(...reentrancyChains);

    // 2. Cross-contract state dependencies
    const stateDeps = this._findStateDependencies(registry);
    findings.push(...stateDeps);

    // 3. Callback reentrancy via ERC777/ERC721 hooks
    const callbackChains = this._findCallbackChains(registry);
    findings.push(...callbackChains);

    // 4. Composability attacks (vault + strategy + token interactions)
    const composability = this._findComposabilityAttacks(registry);
    findings.push(...composability);

    // 5. Inheritance conflicts across files
    const inheritanceConflicts = this._findInheritanceConflicts(registry);
    findings.push(...inheritanceConflicts);

    // 6. Cross-contract access control gaps
    const accessGaps = this._findCrossContractAccessGaps(registry);
    findings.push(...accessGaps);

    return findings;
  }

  _buildRegistry(parsedResults) {
    const registry = {};

    for (const file of parsedResults) {
      if (file.error) continue;
      for (const contract of file.contracts || []) {
        registry[contract.name] = {
          file: file.file,
          contract,
          functions: contract.functions || [],
          stateVariables: contract.stateVariables || [],
          externalCalls: contract.externalCalls || [],
          inheritance: contract.inheritance || [],
          modifiers: contract.modifiers || [],
          events: contract.events || [],
          hasFallback: contract.hasFallback,
          hasReceive: contract.hasReceive,
        };
      }
    }

    // Resolve inheritance: merge parent functions/vars into children
    for (const [name, entry] of Object.entries(registry)) {
      for (const parent of entry.inheritance) {
        const parentEntry = registry[parent];
        if (parentEntry) {
          // Mark which functions come from parent
          for (const fn of parentEntry.functions) {
            if (!entry.functions.some(f => f.name === fn.name)) {
              entry.functions.push({ ...fn, inheritedFrom: parent });
            }
          }
        }
      }
    }

    return registry;
  }

  _findReentrancyChains(registry) {
    const findings = [];

    // Build call graph across contracts
    const callGraph = {};
    for (const [name, entry] of Object.entries(registry)) {
      callGraph[name] = {};
      for (const fn of entry.functions) {
        if (!fn.body) continue;
        const calls = [...fn.body.matchAll(/(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*\(/g)];
        if (calls.length > 0) {
          callGraph[name][fn.name] = calls.map(c => ({
            targetContract: this._resolveTarget(c[1], registry, name),
            targetMethod: c[1],
            callType: c[2],
          }));
        }
      }
    }

    // Find chains: A.fn1 -> B.fn2 -> A.fn3 (reentrancy)
    for (const [contractA, fnsA] of Object.entries(callGraph)) {
      for (const [fn1, calls] of Object.entries(fnsA)) {
        for (const call of calls) {
          const targetContract = call.targetContract;
          if (!targetContract || !callGraph[targetContract]) continue;

          // Check if target contract calls back into contractA
          for (const [fn2, calls2] of Object.entries(callGraph[targetContract])) {
            for (const call2 of calls2) {
              if (call2.targetContract === contractA) {
                // Found chain: A.fn1 -> target.fn2 -> A.fn3
                const isCEIViolation = this._checkCEIInFunction(registry[contractA], fn1);
                if (isCEIViolation) {
                  findings.push({
                    title: `Cross-Contract Reentrancy: ${contractA}.${fn1}() → ${targetContract}.${fn2}() → ${contractA}.${call2.targetMethod}`,
                    severity: 'critical',
                    skill: 'cross-contract',
                    evidence: `Call chain: ${contractA}.${fn1}() calls ${targetContract}.${fn2}() via .${call.callType}(), which calls back into ${contractA}.${call2.targetMethod}() via .${call2.callType}()`,
                    impact: `Cross-contract reentrancy — state in ${contractA} not updated before callback from ${targetContract}`,
                    remediation: `Add reentrancy guard to ${contractA}.${fn1}(), follow CEI pattern, or use pull-payment pattern`,
                    contracts: [contractA, targetContract],
                    chain: [`${contractA}.${fn1}`, `${targetContract}.${fn2}`, `${contractA}.${call2.targetMethod}`],
                  });
                }
              }
            }
          }
        }
      }
    }

    return findings;
  }

  _findStateDependencies(registry) {
    const findings = [];

    // Find contracts that share state variable names (potential storage collision in proxies)
    const varMap = {};
    for (const [name, entry] of Object.entries(registry)) {
      for (const sv of entry.stateVariables) {
        if (!varMap[sv.name]) varMap[sv.name] = [];
        varMap[sv.name].push({ contract: name, type: sv.type, visibility: sv.visibility });
      }
    }

    // Same-named state vars across contracts that interact
    for (const [varName, entries] of Object.entries(varMap)) {
      if (entries.length > 1) {
        const interacting = entries.filter(e =>
          Object.keys(registry).some(other =>
            other !== e.contract &&
            registry[other].externalCalls.some(c => c.target === e.contract)
          )
        );
        if (interacting.length > 1) {
          findings.push({
            title: `Cross-Contract State Dependency: ${varName} exists in ${interacting.map(e => e.contract).join(' and ')}`,
            severity: 'medium',
            skill: 'cross-contract',
            evidence: `Variable ${varName} declared in: ${interacting.map(e => `${e.contract} (${e.type}, ${e.visibility})`).join(', ')}`,
            impact: `State variable ${varName} in multiple interacting contracts — accounting inconsistency if they reference each other's state`,
            remediation: `Use explicit cross-contract reads (getter functions) instead of assuming state consistency`,
            contracts: interacting.map(e => e.contract),
          });
        }
      }
    }

    return findings;
  }

  _findCallbackChains(registry) {
    const findings = [];

    // Find contracts that implement onERC721Received, onERC1155Received, tokensReceived (ERC777)
    for (const [name, entry] of Object.entries(registry)) {
      const callbackFns = entry.functions.filter(fn =>
        /onERC721Received|onERC1155Received|onERC1155BatchReceived|tokensReceived/i.test(fn.name)
      );

      if (callbackFns.length > 0) {
        // Check if callback modifies state or makes external calls
        for (const cb of callbackFns) {
          if (!cb.body) continue;
          const hasStateWrite = /\w+\s*(=|\+=|-=)\s/.test(cb.body);
          const hasExternalCall = /(\w+)\.(call|delegatecall|transfer|send)\s*\(/.test(cb.body);

          if (hasStateWrite || hasExternalCall) {
            // Find which contracts send tokens to this contract
            const senders = Object.entries(registry)
              .filter(([n, e]) => n !== name && e.functions.some(fn =>
                /safeTransferFrom|safeBatchTransferFrom|send|transfer/i.test(fn.name) &&
                fn.body && fn.body.includes(name)
              ))
              .map(([n]) => n);

            if (senders.length > 0) {
              findings.push({
                title: `Callback Reentrancy: ${name}.${cb.name}() modifies state during token callback from ${senders.join('/')}`,
                severity: 'high',
                skill: 'cross-contract',
                evidence: `${cb.name}() has ${hasStateWrite ? 'state writes' : ''} ${hasExternalCall ? 'external calls' : ''} — called when ${senders.join('/')} sends tokens`,
                impact: `Token transfer triggers callback that modifies state — reentrancy via token hook`,
                remediation: `Add reentrancy guard to ${cb.name}(), or use checks-effects-interactions pattern`,
                contracts: [name, ...senders],
              });
            }
          }
        }
      }
    }

    return findings;
  }

  _findComposabilityAttacks(registry) {
    const findings = [];

    // Vault + Strategy pattern: vault delegates to strategy, strategy calls back
    const vaults = Object.entries(registry).filter(([n, e]) =>
      /vault|pool/i.test(n) || e.functions.some(f => /deposit|withdraw|harvest/i.test(f.name))
    );

    for (const [vaultName, vaultEntry] of vaults) {
      const investFns = vaultEntry.functions.filter(f => /invest|harvest|rebalance|earn|compound/i.test(f.name));
      for (const fn of investFns) {
        if (!fn.body) continue;
        const calls = [...fn.body.matchAll(/(\w+)\.(call|delegatecall)\s*\(/g)];
        for (const call of calls) {
          const strategy = this._resolveTarget(call[1], registry, vaultName);
          if (strategy && registry[strategy]) {
            // Check if strategy can manipulate vault state
            const strategyFns = registry[strategy].functions;
            const hasWithdraw = strategyFns.some(f => /withdraw|exit|reclaim/i.test(f.name));
            const strategyCallsVault = strategyFns.some(f =>
              f.body && f.body.includes(vaultName)
            );

            if (hasWithdraw || strategyCallsVault) {
              findings.push({
                title: `Composability Risk: ${vaultName}.${fn.name}() delegates to ${strategy} which can call back into vault`,
                severity: 'high',
                skill: 'cross-contract',
                evidence: `Vault ${vaultName} calls strategy ${strategy} in ${fn.name}(), strategy can ${hasWithdraw ? 'withdraw funds' : ''} ${strategyCallsVault ? 'call back into vault' : ''}`,
                impact: `Strategy contract can manipulate vault during harvest/rebalance — rug pull or accounting manipulation`,
                remediation: `Add reentrancy guard, validate strategy return values, use trusted strategy whitelist`,
                contracts: [vaultName, strategy],
              });
            }
          }
        }
      }
    }

    return findings;
  }

  _findInheritanceConflicts(registry) {
    const findings = [];

    for (const [name, entry] of Object.entries(registry)) {
      if (entry.inheritance.length < 2) continue;

      // Check for diamond problem: same function name from multiple parents
      const parentFunctions = {};
      for (const parent of entry.inheritance) {
        const parentEntry = registry[parent];
        if (!parentEntry) continue;
        for (const fn of parentEntry.functions) {
          if (!parentFunctions[fn.name]) parentFunctions[fn.name] = [];
          parentFunctions[fn.name].push(parent);
        }
      }

      for (const [fnName, parents] of Object.entries(parentFunctions)) {
        if (parents.length > 1) {
          // Check if child overrides
          const hasOverride = entry.functions.some(f => f.name === fnName && f.isOverride);
          if (!hasOverride) {
            findings.push({
              title: `Inheritance Conflict: ${name} inherits ${fnName}() from ${parents.join(' and ')} without override`,
              severity: 'medium',
              skill: 'cross-contract',
              evidence: `Diamond problem: ${parents.join(' and ')} both define ${fnName}() — C3 linearization decides which runs`,
              impact: `Wrong function may be called — ${parents[0]}'s ${fnName}() runs but ${parents[1]}'s was intended`,
              remediation: `Add explicit override in ${name} to specify which parent's ${fnName}() should be used`,
              contracts: [name, ...parents],
            });
          }
        }
      }
    }

    return findings;
  }

  _findCrossContractAccessGaps(registry) {
    const findings = [];

    // Find contracts that can be called by any contract but have privileged operations
    for (const [name, entry] of Object.entries(registry)) {
      const privilegedFns = entry.functions.filter(f =>
        f.visibility === 'external' && f.mutability !== 'view' && f.mutability !== 'pure' &&
        /set|update|change|configure|admin|owner|govern/i.test(f.name)
      );

      for (const fn of privilegedFns) {
        const hasGuard = (fn.modifiers || []).some(m => /only|admin|owner|role/i.test(m)) ||
          (fn.body && /require\s*\(/i.test(fn.body));

        if (!hasGuard) {
          // Check if other contracts can reach this function
          const callers = Object.entries(registry)
            .filter(([n, e]) => n !== name && e.functions.some(f =>
              f.body && f.body.includes(name) && f.body.includes(fn.name)
            ))
            .map(([n]) => n);

          if (callers.length > 0) {
            findings.push({
              title: `Cross-Contract Access Gap: ${name}.${fn.name}() has no guard but is called by ${callers.join(', ')}`,
              severity: 'high',
              skill: 'cross-contract',
              evidence: `${fn.name}() is external with no access control, called by ${callers.join(', ')}`,
              impact: `Compromised caller contract can invoke ${fn.name}() on ${name} — privilege escalation across contracts`,
              remediation: `Add access control to ${fn.name}() or validate caller identity`,
              contracts: [name, ...callers],
            });
          }
        }
      }
    }

    return findings;
  }

  _resolveTarget(targetName, registry, sourceContract) {
    // Try to resolve a call target to a known contract
    if (registry[targetName]) return targetName;

    // Check if source contract has a state variable matching the target
    const source = registry[sourceContract];
    if (source) {
      const sv = source.stateVariables.find(v => v.name === targetName);
      if (sv && sv.type && registry[sv.type]) return sv.type;
    }

    // Check common patterns: strategy, pool, token, underlying
    const patterns = {
      strategy: Object.keys(registry).find(n => /strategy/i.test(n)),
      pool: Object.keys(registry).find(n => /pool/i.test(n)),
      token: Object.keys(registry).find(n => /token/i.test(n)),
      underlying: Object.keys(registry).find(n => /underlying|asset/i.test(n)),
    };
    for (const [pattern, match] of Object.entries(patterns)) {
      if (targetName.toLowerCase().includes(pattern) && match) return match;
    }

    return null;
  }

  _checkCEIInFunction(entry, fnName) {
    const fn = entry.functions.find(f => f.name === fnName);
    if (!fn || !fn.body) return false;

    const body = fn.body;
    const callIdx = body.search(/(\w+)\.(call|delegatecall|staticcall|transfer|send)\s*\(/i);
    if (callIdx === -1) return false;

    const afterCall = body.substring(callIdx);
    return /\w+\s*(=|\+=|-=)\s/.test(afterCall);
  }
}

module.exports = CrossContractAnalyzer;
