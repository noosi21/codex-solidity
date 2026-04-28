## [Severity] Title of the Vulnerability

**Protocol:** [Protocol Name]
**Contract:** [Contract Name] at [File Path]
**Function:** [Function Name]
**Severity:** [Critical / High / Medium / Low]
**SWC ID:** [SWC-XXX if applicable]

---

### Description

[Detailed explanation of the logic flaw. What the code does wrong, why it's vulnerable, and what invariant is broken.]

### Impact

[Quantified financial impact. How funds are lost or protocol is broken. Include:]
- **Estimated Loss:** [X ETH / $Y USD]
- **Affected Users:** [Number or percentage of users]
- **TVL at Risk:** [Percentage of Total Value Locked]
- **Attack Cost:** [How much the attacker needs to spend]

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "[TargetContract].sol";

contract ExploitTest is Test {
    TargetContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    
    function setUp() public {
        // Deploy target contract
        target = new TargetContract();
        // Fund victim
        deal(victim, 100 ether);
    }
    
    function testExploit() public {
        // Step 1: Initial state
        uint256 poolBefore = address(target).balance;
        
        // Step 2: Attacker action
        vm.startPrank(attacker);
        // [Attacker exploit steps here]
        vm.stopPrank();
        
        // Step 3: Verify broken invariant
        // [Assertion showing invariant is broken]
        
        // Step 4: Financial impact
        uint256 poolAfter = address(target).balance;
        assertGt(poolBefore - poolAfter, 0, "Funds were drained");
    }
}
```

### Attack Flow

1. [Step 1: Attacker preparation]
2. [Step 2: Trigger vulnerability]
3. [Step 3: Exploit the broken invariant]
4. [Step 4: Extract funds/value]
5. [Step 5: Result — quantified loss]

### Recommended Mitigation

[Step-by-step fix with code examples:]

```solidity
// Before (vulnerable):
function withdraw(uint256 amount) external {
    // [Vulnerable code]
}

// After (fixed):
function withdraw(uint256 amount) external nonReentrant {
    // [Fixed code with proper checks-effects-interactions pattern]
}
```

### References

- [SWC Registry link if applicable]
- [Similar real-world exploit if known]
- [OpenZeppelin documentation for recommended pattern]
