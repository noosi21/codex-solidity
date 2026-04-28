module.exports = {
  name: 'timestamp-dependence',
  aliases: ['block-timestamp', 'time-manipulation'],
  severity: 'medium',
  description: 'Timestamp Dependence — block.timestamp can be manipulated by miners/validators within ~15s window',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        // Pattern 1: block.timestamp used for randomness
        if (/block\.timestamp/i.test(source)) {
          const timestampUsages = this._findTimestampUsages(source, contract);

          for (const usage of timestampUsages) {
            if (usage.isRandomness) {
              findings.push({
                title: `Timestamp as Randomness — ${usage.function}() uses block.timestamp for entropy`,
                severity: 'high',
                contract: `${contract.name} (${file.file})`,
                function: usage.function,
                evidence: { code: usage.code, pattern: 'block.timestamp used as randomness source' },
                impact: 'Miners/validators can manipulate block.timestamp within a ~15 second window. They can choose a timestamp that produces a favorable outcome for lotteries, games, or any randomness-dependent logic. If prizes involve token rewards, attacker can always win.',
                remediation: 'Use Chainlink VRF for randomness. Never use block.timestamp or block.difficulty as entropy.',
                poc: {
                  attackFlow: [
                    '1. Contract uses block.timestamp % N to select winner',
                    '2. Miner sees pending transactions',
                    '3. Miner calculates which timestamp produces their desired outcome',
                    '4. Miner sets block.timestamp within the ~15s valid window',
                    '5. Miner always wins — reward pool drained',
                  ],
                },
              });
            }

            if (usage.isTimeLock) {
              findings.push({
                title: `Timestamp-Dependent Time Lock — ${usage.function}() can be manipulated by miners`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                function: usage.function,
                evidence: { code: usage.code, pattern: 'block.timestamp used for time-based access control' },
                impact: `Time-based restrictions using block.timestamp can be manipulated by miners within ~15 seconds. If the time window is small (e.g., "can withdraw after 1 hour"), a miner could slightly shift the timestamp to bypass the lock early. For large time windows (days/weeks), the 15s manipulation window is negligible.`,
                remediation: 'For short time windows, consider using block numbers instead. For long time windows, block.timestamp is acceptable. Always document the assumed miner manipulation tolerance.',
                poc: { attackFlow: ['1. Contract requires block.timestamp >= startTime + 1 hour', '2. Miner manipulates timestamp by +15 seconds', '3. Withdrawal enabled 15 seconds early', '4. For 1-hour lock: 15s is negligible. For 60-second lock: 15s is 25% of the window'] },
              });
            }

            if (usage.isInterestCalc) {
              findings.push({
                title: `Timestamp-Dependent Interest — ${usage.function}() uses block.timestamp for yield calculation`,
                severity: 'medium',
                contract: `${contract.name} (${file.file})`,
                function: usage.function,
                evidence: { code: usage.code, pattern: 'block.timestamp used for interest/yield calculation' },
                impact: 'Interest calculations based on block.timestamp can be slightly manipulated by miners (up to ~15 seconds). This gives a small advantage in yield calculations. For high-value DeFi protocols, even small timestamp manipulation can be profitable when combined with flash loans.',
                remediation: 'Use block.number for interest accrual (more predictable). Or accept the ~15s manipulation window as negligible for long-term yield.',
                poc: { scenario: 'Miner advances timestamp by 15s → interest accrues slightly faster → small but consistent profit over many blocks' },
              });
            }
          }
        }

        // Pattern 2: block.number used for short time periods (also manipulable)
        if (/block\.number/i.test(source)) {
          const blockNumUsages = this._findBlockNumberUsages(source, contract);
          for (const usage of blockNumUsages) {
            if (usage.isShortPeriod) {
              findings.push({
                title: `Block Number Short Period — ${usage.function}() uses block.number for short time window`,
                severity: 'low',
                contract: `${contract.name} (${file.file})`,
                function: usage.function,
                evidence: { code: usage.code },
                impact: 'Block number is used for a short time period. Block times vary (Ethereum: ~12s, but can vary). Short time windows based on block numbers may not accurately represent the intended time duration.',
                remediation: 'For precise short time windows, use block.timestamp. For longer periods, block.number is more manipulation-resistant.',
                poc: { scenario: 'Assume 1 block = 12 seconds, but actual time varies 10-14 seconds' },
              });
            }
          }
        }
      }
    }
    return findings;
  },

  _findTimestampUsages(source, contract) {
    const usages = [];
    for (const fn of contract.functions || []) {
      const fnBody = this._extractFunctionBody(source, fn.name);
      if (!fnBody || !/block\.timestamp/i.test(fnBody)) continue;

      const code = fnBody.match(/block\.timestamp[^;]{0,80}/)?.[0];

      const isRandomness = /block\.timestamp\s*%\s*\d|block\.timestamp\s*&\s*\d|keccak256.*block\.timestamp|random.*block\.timestamp/i.test(fnBody);
      const isTimeLock = /block\.timestamp\s*[><=!]+\s*\w+|require.*block\.timestamp|if.*block\.timestamp/i.test(fnBody) && !isRandomness;
      const isInterestCalc = /rate|yield|interest|accrue|reward|apr|apy/i.test(fnBody) && !isRandomness;

      usages.push({ function: fn.name, code, isRandomness, isTimeLock, isInterestCalc });
    }
    return usages;
  },

  _findBlockNumberUsages(source, contract) {
    const usages = [];
    for (const fn of contract.functions || []) {
      const fnBody = this._extractFunctionBody(source, fn.name);
      if (!fnBody || !/block\.number/i.test(fnBody)) continue;

      const code = fnBody.match(/block\.number[^;]{0,80}/)?.[0];
      const isShortPeriod = /block\.number\s*[+-]\s*\d{1,3}\b/.test(fnBody);

      usages.push({ function: fn.name, code, isShortPeriod });
    }
    return usages;
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
