module.exports = {
  name: 'self-destruct',
  aliases: ['force-feed', 'force-eth', 'selfdestruct'],
  severity: 'high',
  description: 'Self-Destruct / Force Feed — break accounting by forcing ETH into contract, lock or drain funds',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: Contract uses address(this).balance for accounting
        const usesAddressBalance = /address\s*\(\s*this\s*\)\s*\.balance|address\s*\(\s*this\s*\)\s*balance/i.test(source);
        const hasTrackedBalance = /totalDeposits|totalBalance|_totalBalance|poolBalance|accountedBalance/i.test(source);

        if (usesAddressBalance && !hasTrackedBalance) {
          findings.push({
            title: `Force Feed Vulnerability — contract uses address(this).balance for accounting`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: {
              pattern: 'address(this).balance used for critical logic',
              code: source.match(/address\s*\(\s*this\s*\)\s*\.balance[^;]{0,80}/)?.[0],
              noTrackedBalance: true,
            },
            impact: `An attacker can force ETH into this contract via selfdestruct() on another contract. This ETH is NOT tracked by the contract's accounting. Two exploitation paths:

**Path 1 — Fund Drain:** If withdrawals are based on address(this).balance, the forced ETH makes the contract appear richer than it should be. Attacker can withdraw MORE than they deposited, stealing other users' funds.

**Path 2 — Permanent Freeze:** If the contract has a "sweep excess" function or checks that address(this).balance matches tracked deposits, the forced ETH breaks the invariant. This can cause all operations to revert, permanently locking ALL user funds.`,
            remediation: 'Never use address(this).balance for accounting. Track deposits in a separate state variable (totalDeposits). Only use tracked balance for withdrawal calculations. Ignore any ETH received outside normal deposit flows.',
            poc: {
              type: 'exploit_contract',
              code: impactEngine.generateExploitCode('selfDestruct'),
              attackFlowDrain: [
                '1. Contract has 100 ETH from user deposits',
                '2. Contract tracks: userA=50ETH, userB=50ETH',
                '3. Attacker selfdestructs contract with 100 ETH forced into target',
                '4. address(this).balance now = 200 ETH',
                '5. If withdrawal uses address(this).balance, userA can withdraw 100 ETH (double)',
                '6. userB tries to withdraw — contract insolvent',
              ],
              attackFlowFreeze: [
                '1. Contract requires address(this).balance == totalDeposits',
                '2. Attacker forces 1 wei via selfdestruct',
                '3. address(this).balance = totalDeposits + 1',
                '4. Invariant broken — ALL operations revert',
                '5. ALL user funds permanently locked',
              ],
            },
          });
        }

        // Pattern 2: Contract with receive/fallback that doesn't account for forced ETH
        if (contract.hasReceive || contract.hasFallback) {
          const receiveBody = this._extractReceiveBody(source);
          if (receiveBody && !/emit|Deposit|deposit/i.test(receiveBody)) {
            findings.push({
              title: `Untracked receive() — ETH received without accounting`,
              severity: 'medium',
              contract: `${contract.name} (${file.file})`,
              evidence: { hasReceive: contract.hasReceive, receiveBody: receiveBody.substring(0, 200) },
              impact: 'Contract accepts ETH via receive() but may not properly account for it. If forced ETH arrives (via selfdestruct or direct send), it can break balance assumptions and lead to fund drain or freeze.',
              remediation: 'Track all incoming ETH in a state variable. Emit events for all deposits. Consider reverting unexpected ETH transfers.',
              poc: { attackFlow: ['1. Attacker sends ETH to contract via selfdestruct', '2. ETH not tracked in accounting', '3. Balance mismatch causes issues'] },
            });
          }
        }

        // Pattern 3: Selfdestruct in contract (can be used to kill contract)
        if (/selfdestruct\s*\(|suicide\s*\(/i.test(source)) {
          const selfdestructFns = contract.functions?.filter(fn => {
            const body = this._extractFunctionBody(source, fn.name);
            return body && /selfdestruct|suicide/i.test(body);
          }) || [];

          for (const fn of selfdestructFns) {
            const hasAuth = fn.modifiers?.some(m => /onlyOwner|onlyAdmin/i.test(m));
            findings.push({
              title: `Selfdestruct in ${fn.name}() — ${hasAuth ? 'owner can kill contract' : 'ANYONE can kill contract'}`,
              severity: hasAuth ? 'medium' : 'critical',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { hasAuth, visibility: fn.visibility },
              impact: hasAuth
                ? 'Owner can selfdestruct the contract, sending all ETH to themselves and making the contract unusable. All user funds are sent to owner. This is a centralization/rug pull risk.'
                : 'Anyone can call selfdestruct to kill the contract. All ETH sent to the caller. All user funds stolen. Contract becomes permanently unusable — all state is cleared.',
              remediation: 'Remove selfdestruct unless absolutely necessary. If needed, add onlyOwner + timelock. Consider using disable() instead of destroy.',
              poc: {
                attackFlow: hasAuth
                  ? ['1. Compromised/malicious owner calls selfdestruct()', '2. Contract destroyed', '3. All ETH sent to owner', '4. Users cannot interact — funds gone']
                  : ['1. Attacker calls selfdestruct(payable(attacker))', '2. Contract destroyed immediately', '3. All ETH sent to attacker address', '4. All user funds stolen, contract dead'],
              },
            });
          }
        }

        // Pattern 4: ETH stuck forever — no withdrawal mechanism
        const hasWithdrawal = contract.functions?.some(fn => /withdraw|claim|redeem|exit|cash|sweep|rescue/i.test(fn.name)) || false;
        const acceptsETH = contract.hasReceive || contract.hasFallback || contract.functions?.some(fn => fn.mutability === 'payable');

        if (acceptsETH && !hasWithdrawal) {
          findings.push({
            title: `ETH Locked Forever — contract accepts ETH but has no withdrawal function`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { acceptsETH, noWithdrawal: true },
            impact: 'Contract can receive ETH (via receive/fallback/payable functions) but has no way to send ETH out. Any ETH sent to this contract is permanently locked. This includes forced ETH via selfdestruct.',
            remediation: 'Add a withdrawal/sweep function with proper access control. Or revert on unexpected ETH receipt.',
            poc: { scenario: 'ETH sent to contract can never be recovered — permanent fund lock' },
          });
        }

        // Pattern 5: CREATE2 deployment with selfdestruct for redeployment
        if (/CREATE2|create2/i.test(source) && /selfdestruct/i.test(source)) {
          findings.push({
            title: `CREATE2 + Selfdestruct — contract can be redeployed with different code`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { pattern: 'CREATE2 deployment with selfdestruct in contract' },
            impact: 'If a contract is deployed via CREATE2 and contains selfdestruct, it can be destroyed and redeployed at the SAME address with DIFFERENT code. This breaks all trust assumptions — users who verified the original code are now interacting with completely different code at the same address.',
            remediation: 'Remove selfdestruct from CREATE2-deployed contracts. Use disable pattern instead of destroy.',
            poc: {
              attackFlow: [
                '1. Contract deployed at address X via CREATE2',
                '2. Users trust the code and deposit funds',
                '3. Attacker selfdestructs the contract',
                '4. Attacker redeploys at SAME address X with malicious code',
                '5. Users interact with same address, now running malicious code',
                '6. All funds drained via backdoor in redeployed contract',
              ],
            },
          });
        }
      }
    }
    return findings;
  },

  _extractReceiveBody(source) {
    const receiveRe = /receive\s*\(\s*\)\s*(?:external\s+)?payable\s*\{/g;
    const match = receiveRe.exec(source);
    if (!match) return null;
    const start = source.indexOf('{', match.index) + 1;
    let depth = 1;
    for (let i = start; i < source.length; i++) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') { depth--; if (depth === 0) return source.substring(start, i); }
    }
    return source.substring(start);
  },

  _extractFunctionBody(source, fnName) {
    const fnRe = new RegExp(`function\\s+${fnName}\\s*\\([^)]*\\)[^{]*\\{`, 'g');
    const match = fnRe.exec(source);
    if (!match) return null;
    const start = source.indexOf('{', match.index) + 1;
    let depth = 1;
    for (let i = start; i < source.length; i++) {
      if (source[i] === '{') depth++;
      else if (source[i] === '}') { depth--; if (depth === 0) return source.substring(start, i); }
    }
    return source.substring(start);
  },
};
