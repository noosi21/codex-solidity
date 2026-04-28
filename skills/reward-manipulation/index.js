module.exports = {
  name: 'reward-manipulation',
  aliases: ['reward-gaming', 'staking-manipulation', 'reward-drain'],
  severity: 'high',
  description: 'Reward Manipulation — stake/unstake to claim rewards multiple times, reward rate gaming',
  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;
    const fs = require('fs');

    for (const file of contracts) {
      if (file.error) continue;
      const source = fs.readFileSync(file.file, 'utf8');

      for (const contract of file.contracts || []) {
        const hasRewards = /reward|staking|claim|harvest|earn|accrued|rewardRate|rewardPerToken/i.test(source);
        if (!hasRewards) continue;

        // Pattern 1: Claim rewards without resetting accumulator — double claim
        const claimFns = contract.functions?.filter(fn => /claim|harvest|getReward|earn|withdrawReward/i.test(fn.name)) || [];
        for (const fn of claimFns) {
          const fnBody = this._extractFunctionBody(source, fn.name);
          if (!fnBody) continue;

          const resetsAccumulator = /reward.*=.*0|rewardDebt|reward\s*-=\s*reward|paid\s*=\s*accrued|userReward\s*=\s*0/i.test(fnBody);
          if (!resetsAccumulator) {
            findings.push({
              title: `Double Reward Claim — ${fn.name}() doesn't reset reward accumulator`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              function: fn.name,
              evidence: { noReset: true },
              impact: `${fn.name}() pays out rewards but doesn't reset the user's reward accumulator. User can call ${fn.name}() repeatedly and receive the same reward amount each time. This drains the reward pool — all other stakers lose their rewards.`,
              remediation: `After paying rewards, set user's accumulated reward to 0: userRewards[msg.sender] = 0; Or use rewardDebt pattern from Synthetix staking.`,
              poc: { attackFlow: [`1. User stakes tokens, accumulates 100 reward tokens`, `2. User calls ${fn.name}() → receives 100 tokens`, '3. Reward accumulator NOT reset', `4. User calls ${fn.name}() again → receives 100 tokens again`, '5. Repeat until reward pool empty', '6. All other stakers get nothing'] },
            });
          }
        }

        // Pattern 2: Reward rate not bounded — owner can set infinite rewards
        const hasRewardRateCap = /rewardRate\s*<|rewardRate\s*<=|maxRewardRate|require.*rewardRate/i.test(source);
        if (!hasRewardRateCap && /rewardRate|reward_rate/i.test(source)) {
          findings.push({
            title: `Unbounded Reward Rate — owner can set infinite rewards, drain reward token pool`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { noRewardRateCap: true },
            impact: 'Owner can set rewardRate to any value. If set higher than the contract\'s reward token balance, the contract promises rewards it cannot pay. This creates bad debt — stakers accumulate "rewards" that don\'t exist. When they try to claim, the contract reverts (DOS) or pays out empty.',
            remediation: 'Cap rewardRate based on reward token balance: require(rewardRate <= rewardBalance / duration). Add timelock to reward rate changes.',
            poc: { attackFlow: ['1. Malicious/compromised owner sets rewardRate = 1e30', '2. Stakers accumulate massive "rewards"', '3. Contract only has 1000 actual reward tokens', '4. First staker claims → gets all 1000 tokens', '5. Remaining stakers cannot claim — contract empty', '6. OR: all claims revert — DOS'] },
          });
        }

        // Pattern 3: Stake → claim → unstake → restake loop (reward rate gaming)
        const stakeFns = contract.functions?.filter(fn => /stake|deposit|enter/i.test(fn.name)) || [];
        const unstakeFns = contract.functions?.filter(fn => /unstake|withdraw|exit/i.test(fn.name)) || [];
        if (stakeFns.length > 0 && unstakeFns.length > 0 && claimFns.length > 0) {
          const hasCooldown = /cooldown|lockup|lock.*period|unstake.*delay|withdraw.*delay/i.test(source);
          if (!hasCooldown) {
            findings.push({
              title: `No Stake Cooldown — attacker can stake/claim/unstake loop to drain rewards`,
              severity: 'high',
              contract: `${contract.name} (${file.file})`,
              evidence: { noCooldown: true },
              impact: 'No cooldown between staking and unstaking. Attacker can: (1) stake right before reward distribution, (2) claim rewards, (3) unstake immediately, (4) repeat. This is the "flash stake" attack — attacker gets rewards without any time commitment, diluting honest long-term stakers\' rewards.',
              remediation: 'Add cooldown period between staking and unstaking. Use time-weighted reward calculations. Require minimum stake duration for reward eligibility.',
              poc: { attackFlow: ['1. Attacker stakes large amount right before reward snapshot', '2. Gets proportional share of rewards', '3. Immediately unstakes (no cooldown)', '4. Claims rewards', '5. Repeats each reward period', '6. Gets rewards without any time commitment'] },
            });
          }
        }

        // Pattern 4: Reward token == staking token — inflation exploit
        if (/rewardToken.*=.*stakingToken|reward.*=.*staked|_rewardToken.*_stakingToken/i.test(source)) {
          findings.push({
            title: `Reward Token = Staking Token — inflation exploit possible`,
            severity: 'high',
            contract: `${contract.name} (${file.file})`,
            evidence: { sameToken: true },
            impact: 'Reward token is the same as staking token. This creates an inflation loop: staking rewards mint/distribute more of the same token, which can be staked for more rewards. If reward rate > 0, total supply grows unboundedly. Attacker can compound stake+claim in loops to extract maximum value.',
            remediation: 'Use a different token for rewards. Or cap total reward supply. Add compound cooldown.',
            poc: { attackFlow: ['1. Stake 100 tokens → earn 10 tokens/day as reward', '2. Claim 10 tokens → stake them too', '3. Now earning 11 tokens/day', '4. Compound repeatedly → exponential growth', '5. Attacker with large initial stake dominates reward pool'] },
          });
        }

        // Pattern 5: New staker gets historical rewards (rewardPerToken not stored)
        const hasRewardPerTokenStored = /rewardPerTokenStored|rewardPerShare|accRewardPerShare|rewardPerTokenPaid/i.test(source);
        if (!hasRewardPerTokenStored) {
          findings.push({
            title: `Missing Reward Per Token Accumulator — new stakers may claim historical rewards`,
            severity: 'medium',
            contract: `${contract.name} (${file.file})`,
            evidence: { noAccumulator: true },
            impact: 'Reward distribution doesn\'t use the reward-per-token accumulator pattern (Synthetix pattern). Without tracking each user\'s last claimed reward per token, new stakers may claim rewards that were earned before they staked, or existing stakers may lose rewards when new stakers join.',
            remediation: 'Implement Synthetix reward pattern: rewardPerTokenStored + userRewardPerTokenPaid + earned() calculation.',
            poc: { scenario: 'Staker A earns 100 tokens. Staker B joins. Reward calculation distributes A\'s rewards to B as well.' },
          });
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
