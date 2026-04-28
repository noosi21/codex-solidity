module.exports = {
  name: 'unchecked-returns',
  aliases: ['unchecked-return-value', 'low-level-call'],
  severity: 'high',
  description: 'Unchecked Return Values — low-level .call()/.send() return values ignored, silent failures cause fund loss',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          // Find low-level calls without return value checks
          const vulns = [];

          // .call() without (ok, ) check
          const callMatches = [...fnBody.matchAll(/(\w+)\.call\s*(?:\{[^}]*\})?\s*\(([^)]*)\)/g)];
          for (const m of callMatches) {
            const callStmt = m[0];
            const beforeCall = fnBody.substring(0, fnBody.indexOf(callStmt));
            const afterCall = fnBody.substring(fnBody.indexOf(callStmt) + callStmt.length, fnBody.indexOf(callStmt) + callStmt.length + 200);

            // Check if return value is captured and checked
            const capturesReturn = /bool\s+\w+\s*=\s*\w+\.call|(\(ok[,\)]|\(success[,\)])/.test(beforeCall + callStmt);
            const checksReturn = /require\s*\(\s*(ok|success|ret|result)|if\s*\(\s*!(ok|success|ret|result)|if\s*\(\s*(ok|success|ret|result)\s*==\s*false/.test(afterCall) ||
              /require\s*\(\s*\w+\.call/.test(fnBody);

            if (!capturesReturn && !checksReturn) {
              vulns.push({
                type: 'call',
                code: callStmt,
                target: m[1],
                data: m[2]?.substring(0, 50),
                impact: '.call() returns (bool, bytes) — if bool is false, call failed silently. No revert occurs.',
              });
            }
          }

          // .send() without check
          const sendMatches = [...fnBody.matchAll(/(\w+)\.send\s*\(\s*([^)]+)\s*\)/g)];
          for (const m of sendMatches) {
            const sendStmt = m[0];
            const afterSend = fnBody.substring(fnBody.indexOf(sendStmt) + sendStmt.length, fnBody.indexOf(sendStmt) + sendStmt.length + 150);
            const checksReturn = /require\s*\(\s*\w+\.send|if\s*\(\s*!\s*\w+\.send|bool\s+\w+\s*=\s*\w+\.send/.test(fnBody);

            if (!checksReturn) {
              vulns.push({
                type: 'send',
                code: sendStmt,
                target: m[1],
                amount: m[2],
                impact: '.send() returns bool — if false, transfer failed silently. Funds NOT sent but code continues as if they were.',
              });
            }
          }

          // .transfer() — always succeeds or reverts, but check for gas limit issues
          const transferMatches = [...fnBody.matchAll(/(\w+)\.transfer\s*\(\s*([^)]+)\s*\)/g)];
          for (const m of transferMatches) {
            vulns.push({
              type: 'transfer',
              code: m[0],
              target: m[1],
              amount: m[2],
              impact: '.transfer() forwards only 2300 gas — will fail if recipient has gas-intensive fallback. Not a return check issue but causes silent failures in contracts.',
            });
          }

          // ERC20 transfer/transferFrom without SafeERC20
          const erc20Matches = [...fnBody.matchAll(/(\w+)\.(transfer|transferFrom|approve)\s*\(/g)];
          for (const m of erc20Matches) {
            const afterCall = fnBody.substring(fnBody.indexOf(m[0]) + m[0].length, fnBody.indexOf(m[0]) + m[0].length + 100);
            const usesSafeERC20 = /SafeERC20|safeTransfer|safeApprove|safeTransferFrom/.test(fnBody);
            const checksReturn = /require\s*\(\s*\w+\.transfer|require\s*\(\s*\w+\.approve|require\s*\(\s*\w+\.transferFrom/.test(fnBody);

            if (!usesSafeERC20 && !checksReturn && m[2] !== 'transfer') {
              // transferFrom and approve return bool that must be checked
              vulns.push({
                type: 'erc20',
                code: m[0],
                target: m[1],
                method: m[2],
                impact: `ERC20 ${m[2]}() returns bool — tokens like USDT return void instead. Without SafeERC20, call can fail silently and contract continues with incorrect state.`,
              });
            }
          }

          for (const vuln of vulns) {
            const severity = vuln.type === 'call' || vuln.type === 'erc20' ? 'high' : vuln.type === 'send' ? 'high' : 'medium';
            findings.push({
              title: `Unchecked Return Value — ${fn.name}() ignores ${vuln.type}() return value`,
              severity,
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: {
                callType: vuln.type,
                code: vuln.code,
                target: vuln.target,
              },
              impact: vuln.impact + (vuln.type === 'call'
                ? ' If the external call fails, the contract continues execution as if it succeeded. This can cause: (1) funds not transferred but balance decremented — user loses money, (2) state updated based on failed call — accounting broken, (3) attacker can force call failures to manipulate contract state.'
                : vuln.type === 'send'
                ? ' If .send() returns false (out of gas, revert in fallback), the contract continues as if ETH was sent. Balance accounting becomes incorrect — users cannot withdraw correct amounts.'
                : vuln.type === 'erc20'
                ? ' Some ERC20 tokens (USDT, BNB) do NOT return bool on transfer/transferFrom. Calling them without SafeERC20 will revert or silently fail. This breaks all token accounting.'
                : ' Transfer with 2300 gas limit can fail for contracts with complex fallback functions.'),
              remediation: vuln.type === 'erc20'
                ? 'Use OpenZeppelin SafeERC20: safeTransfer(), safeTransferFrom(), safeApprove(). These handle non-standard return values.'
                : vuln.type === 'call'
                ? 'Always check .call() return value: (bool ok, ) = target.call{value: x}(""); require(ok, "CALL_FAILED");'
                : vuln.type === 'send'
                ? 'Replace .send() with .call{value: x}("") and check return value. Or use pull-over-push pattern.'
                : 'Replace .transfer() with .call{value: x}("") and check return value.',
              poc: {
                attackFlow: vuln.type === 'call' ? [
                  `1. Contract calls ${vuln.target}.call() without checking return value`,
                  '2. Attacker makes the called contract revert on purpose',
                  '3. .call() returns (false, "") — but contract ignores the bool',
                  '4. Contract continues as if call succeeded',
                  '5. State updated (e.g., balance decremented) but ETH NOT sent',
                  '6. Accounting broken — user lost funds that were never transferred',
                ] : vuln.type === 'erc20' ? [
                  '1. Contract uses token.transfer() without SafeERC20',
                  '2. Token is USDT which returns void, not bool',
                  '3. ABI expects bool return → EVM revert on unexpected return data',
                  '4. ALL token operations fail — contract is bricked',
                  '5. User funds locked permanently',
                ] : [
                  '1. Contract sends ETH via .send() or .transfer()',
                  '2. Recipient contract has fallback using >2300 gas',
                  '3. Transfer fails silently (.send) or reverts (.transfer)',
                  '4. If .send(): contract continues with wrong accounting',
                  '5. If .transfer(): entire transaction reverts, DOS',
                ],
              },
            });
          }
        }
      }
    }
    return findings;
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
