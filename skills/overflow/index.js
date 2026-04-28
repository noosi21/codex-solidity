module.exports = {
  name: 'overflow',
  aliases: ['underflow', 'integer-overflow', 'integer-underflow', 'arithmetics'],
  severity: 'critical',
  description: 'Integer Overflow/Underflow — user deposits 1 ETH but withdraws 2^256-1 ETH via balance wrapping',
  async execute(ctx) {
    const findings = [];
    const { contracts, impactEngine } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');
      const pragma = file.pragma || '';

      // Solidity <0.8.0 has automatic overflow/underflow
      const isPre08 = /0\.[0-7]\./.test(pragma);
      // Solidity >=0.8.0 has unchecked blocks
      const hasUnchecked = /unchecked\s*\{/.test(source);

      if (!isPre08 && !hasUnchecked) continue;

      for (const contract of file.contracts || []) {
        for (const fn of contract.functions || []) {
          const fnBody = this._extractFunctionBody(source, fn.name, contract.name);
          if (!fnBody) continue;

          // Find unchecked arithmetic operations
          const vulns = this._findArithmeticVulns(fnBody, fn.name, isPre08);
          if (vulns.length === 0) continue;

          for (const vuln of vulns) {
            const calcResult = impactEngine.calcOverflowImpact(
              vuln.operandType === 'underflow' ? 1e18 : 1e18,
              vuln.operandType === 'underflow' ? 2e18 : BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639935').toString(),
              vuln.operandType
            );

            findings.push({
              title: `Integer ${vuln.operandType} — ${fn.name}() ${vuln.operation} without bounds check`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: {
                pragma: pragma || 'not specified',
                isPre08,
                operation: vuln.operation,
                line: vuln.line,
                code: vuln.code,
                uncheckedBlock: vuln.inUnchecked,
                scenario: vuln.scenario,
              },
              impact: vuln.impactDescription + (isPre08
                ? ' Solidity <0.8.0 does NOT check for overflow/underflow — this wraps silently.'
                : ' Inside unchecked{} block, overflow/underflow wraps silently without reverting.') +
                ` Example: User deposits 1 ETH, withdraws 2 ETH → balance underflows from (1-2) to 2^256-1. User now "owns" more ETH than the entire supply. They can withdraw this massive amount, draining the entire pool and all other users' funds.`,
              remediation: isPre08
                ? 'Upgrade to Solidity >=0.8.0 (built-in overflow checks). Or use OpenZeppelin SafeMath for all arithmetic.'
                : 'Remove unchecked{} blocks unless mathematically proven safe. Add explicit require() bounds checks before/after unchecked operations.',
              poc: {
                type: 'exploit_scenario',
                code: impactEngine.generateExploitCode('overflow'),
                attackFlow: vuln.attackFlow,
                mathProof: {
                  operation: vuln.operation,
                  before: '1 ETH (1e18 wei)',
                  after: vuln.operandType === 'underflow'
                    ? '2^256 - 1 wei (~115 quattuorvigintillion ETH) — MORE THAN ALL ETHEREUM IN EXISTENCE'
                    : '0 wei — balance destroyed',
                  result: vuln.operandType === 'underflow'
                    ? 'Attacker withdraws more than they deposited — drains entire pool'
                    : 'Attacker destroys their own balance to manipulate accounting',
                },
                calcResult,
              },
            });
          }
        }

        // Check for specific patterns that enable "withdraw more than deposit"
        const balanceTracking = this._findBalanceTracking(source, contract);
        for (const bt of balanceTracking) {
          if (bt.hasSubtraction && !bt.hasBoundsCheck && (isPre08 || bt.inUnchecked)) {
            findings.push({
              title: `Balance Underflow — user can withdraw MORE than deposited`,
              severity: 'critical',
              contract: `${contract.name} (${file.file})`,
              function: bt.function,
              evidence: {
                variable: bt.variable,
                subtraction: bt.subtraction,
                noBoundsCheck: true,
                pragma: pragma,
              },
              impact: `THIS IS THE "DEPOSIT 1, WITHDRAW INFINITY" BUG. The balance variable ${bt.variable} is decremented without checking if the subtraction would underflow. A user who deposits 1 token can withdraw 2 tokens, causing their balance to underflow to 2^256-1. They can then withdraw this astronomical amount, stealing ALL funds from the contract. Every other user loses their deposits.`,
              remediation: `Add require(${bt.variable} >= amount) before subtraction. Use SafeMath or Solidity >=0.8.0.`,
              poc: {
                attackFlow: [
                  `1. Attacker deposits 1 token → ${bt.variable}[attacker] = 1`,
                  `2. Attacker calls withdraw(2) → ${bt.variable}[attacker] = 1 - 2`,
                  `3. Underflow: ${bt.variable}[attacker] = 2^256 - 1 (massive number)`,
                  `4. Attacker now "owns" more tokens than total supply`,
                  `5. Attacker withdraws repeatedly until contract is empty`,
                  `6. ALL other users' funds stolen — contract is drained`,
                ],
                mathProof: {
                  deposit: '1 token',
                  withdraw: '2 tokens',
                  balanceAfter: '2^256 - 1 tokens (underflow)',
                  poolDrained: 'YES — attacker can withdraw everything',
                },
              },
            });
          }
        }
      }
    }
    return findings;
  },

  _findArithmeticVulns(body, fnName, isPre08) {
    const vulns = [];
    const lines = body.split('\n');

    // Find unchecked blocks
    const uncheckedRanges = [];
    const uncheckedRe = /unchecked\s*\{/g;
    let m;
    while ((m = uncheckedRe.exec(body)) !== null) {
      const start = m.index;
      let depth = 1;
      for (let i = start + m[0].length; i < body.length; i++) {
        if (body[i] === '{') depth++;
        else if (body[i] === '}') { depth--; if (depth === 0) { uncheckedRanges.push([start, i]); break; } }
      }
    }

    const isInUnchecked = (idx) => uncheckedRanges.some(([s, e]) => idx >= s && idx <= e);

    // Find subtraction operations (underflow risk)
    const subRe = /(\w+)\s*-=\s*([^;]+);|(\w+)\s*=\s*(\w+)\s*-\s*([^;]+);/g;
    while ((m = subRe.exec(body)) !== null) {
      const inUnchecked = isInUnchecked(m.index);
      if (isPre08 || inUnchecked) {
        const varName = m[1] || m[3];
        const subAmount = m[2] || m[5];
        vulns.push({
          operandType: 'underflow',
          operation: `${varName} -= ${subAmount}`,
          line: body.substring(0, m.index).split('\n').length,
          code: m[0],
          inUnchecked,
          scenario: `If ${subAmount} > ${varName}, balance underflows to 2^256 - ${subAmount} + ${varName}`,
          impactDescription: `Underflow in ${varName}: subtracting more than the current value wraps to a massive number.`,
          attackFlow: [
            `1. Attacker ensures ${varName} is small (e.g., deposit minimum)`,
            `2. Attacker triggers subtraction of ${subAmount} which exceeds ${varName}`,
            `3. ${varName} underflows to near 2^256`,
            `4. Attacker now has astronomically large balance`,
            `5. Attacker drains entire contract`,
          ],
        });
      }
    }

    // Find addition operations (overflow risk)
    const addRe = /(\w+)\s*\+=\s*([^;]+);|(\w+)\s*=\s*(\w+)\s*\+\s*([^;]+);/g;
    while ((m = addRe.exec(body)) !== null) {
      const inUnchecked = isInUnchecked(m.index);
      if (isPre08 || inUnchecked) {
        const varName = m[1] || m[3];
        const addAmount = m[2] || m[5];
        vulns.push({
          operandType: 'overflow',
          operation: `${varName} += ${addAmount}`,
          line: body.substring(0, m.index).split('\n').length,
          code: m[0],
          inUnchecked,
          scenario: `If ${varName} + ${addAmount} > 2^256-1, value wraps to near zero`,
          impactDescription: `Overflow in ${varName}: adding large values wraps to zero or small number, destroying value.`,
          attackFlow: [
            `1. Attacker makes ${varName} very large`,
            `2. Attacker triggers addition of ${addAmount}`,
            `3. ${varName} overflows, wraps to near zero`,
            `4. Value destroyed — accounting broken`,
          ],
        });
      }
    }

    return vulns;
  },

  _findBalanceTracking(source, contract) {
    const results = [];
    const balanceVars = ['balances', 'balanceOf', '_balances', 'userBalance', 'shares', 'deposits', 'stakes', 'userDeposits'];

    for (const fn of contract.functions || []) {
      const fnBody = this._extractFunctionBody(source, fn.name, contract.name);
      if (!fnBody) continue;

      for (const bv of balanceVars) {
        const hasVar = fnBody.includes(bv);
        if (!hasVar) continue;

        const hasSubtraction = new RegExp(`${bv}\\[.*\\]\\s*-=|${bv}\\[.*\\]\\s*=.*-`).test(fnBody);
        const hasBoundsCheck = new RegExp(`require\\s*\\(\\s*${bv}|${bv}\\s*>=|${bv}\\s*>=\\s*amount`).test(fnBody);
        const inUnchecked = /unchecked\s*\{/.test(fnBody.substring(0, fnBody.indexOf(bv)));

        if (hasSubtraction) {
          results.push({
            variable: bv,
            function: fn.name,
            hasSubtraction: true,
            hasBoundsCheck,
            inUnchecked,
            subtraction: fnBody.match(new RegExp(`${bv}[^;]*-[^;]*;`))?.[0]?.trim() || 'detected',
          });
        }
      }
    }
    return results;
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
