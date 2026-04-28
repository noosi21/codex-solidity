/**
 * Upgradability Pattern Checker Skill
 * Detects common proxy/upgradability vulnerabilities:
 * - Uninitialized proxy (attacker calls initialize())
 * - Missing initializer modifier
 * - UUPS vs Transparent pattern issues
 * - Storage collision in upgrade
 * - Missing __gap for inheritance
 */

const Skill = require('../skill-base');

class UpgradabilitySkill extends Skill {
  constructor() {
    super({
      name: 'upgradability',
      description: 'Proxy upgradability — uninitialized proxy, missing initializer, storage collision, UUPS issues',
      severity: 'critical',
    });
  }

  async execute(ctx) {
    const findings = [];
    const { contracts } = ctx;

    for (const file of contracts || []) {
      for (const contract of file.contracts || []) {
        const name = contract.name;
        const functions = contract.functions || [];
        const stateVars = contract.stateVars || [];
        const modifiers = contract.modifiers || [];
        const inheritance = contract.inheritance || [];

        const isProxy = /proxy|upgrade|transparent|uups/i.test(name);
        const isUpgradeable = inheritance.some(i => /upgradeable|initializable|proxy/i.test(i));
        const hasInitialize = functions.some(f => /^initialize/i.test(f.name));

        // 1. Uninitialized proxy — has initialize() but no initializer modifier
        if (hasInitialize) {
          const initFuncs = functions.filter(f => /^initialize/i.test(f.name));
          for (const init of initFuncs) {
            const hasInitializerModifier = (init.modifiers || []).some(m => /initializer|onlyinitializer/i.test(m));
            if (!hasInitializerModifier) {
              findings.push({
                title: `[Critical] initialize() without initializer modifier in ${name}`,
                severity: 'critical',
                skill: 'upgradability',
                functionName: init.name,
                contract: name,
                evidence: `function ${init.name}() — no 'initializer' modifier — attacker can call initialize() and become owner`,
                impact: 'Attacker front-runs initialization, becomes owner, drains all funds',
              });
            }
          }
        }

        // 2. Proxy contract without any access control on upgrade
        if (isProxy || isUpgradeable) {
          const upgradeFuncs = functions.filter(f => /upgrade|_upgrade|upgradeTo/i.test(f.name));
          for (const upg of upgradeFuncs) {
            const hasAccessControl = (upg.modifiers || []).some(m => /onlyowner|onlyadmin|onlyproxyadmin|onlygovernor/i.test(m));
            if (!hasAccessControl) {
              findings.push({
                title: `[Critical] Unprotected upgrade function in ${name}`,
                severity: 'critical',
                skill: 'upgradability',
                functionName: upg.name,
                contract: name,
                evidence: `function ${upg.name}() — no access control — anyone can upgrade the proxy`,
                impact: 'Anyone can upgrade proxy to malicious implementation — full contract takeover',
              });
            }
          }
        }

        // 3. UUPS pattern — upgrade in implementation, check if _authorizeUpgrade exists
        if (inheritance.some(i => /uupsupgradeable/i.test(i))) {
          const hasAuthorizeUpgrade = functions.some(f => /_authorizeupgrade/i.test(f.name));
          if (!hasAuthorizeUpgrade) {
            findings.push({
              title: `[Critical] UUPS without _authorizeUpgrade in ${name}`,
              severity: 'critical',
              skill: 'upgradability',
              contract: name,
              evidence: `Contract inherits UUPSUpgradeable but doesn't override _authorizeUpgrade()`,
              impact: 'Anyone can call upgradeTo() — upgrade to malicious implementation',
            });
          }
        }

        // 4. Storage collision risk — state vars in upgradeable contract without __gap
        if (isUpgradeable && stateVars.length > 0) {
          const hasGap = stateVars.some(v => /__gap|____gap/i.test(v.name));
          if (!hasGap && inheritance.length > 1) {
            findings.push({
              title: `[High] Upgradeable contract ${name} missing __gap for storage layout`,
              severity: 'high',
              skill: 'upgradability',
              contract: name,
              evidence: `Contract has ${stateVars.length} state vars, ${inheritance.length} parents, but no __gap — adding vars to parent will collide`,
              impact: 'Future upgrades to parent contract will cause storage collision — corrupted state, potential fund loss',
            });
          }
        }

        // 5. Transparent proxy — check if admin functions are properly restricted
        if (inheritance.some(i => /transparentupgradeableproxy/i.test(i))) {
          // Transparent proxy should have proxy admin — check if msg.sender checks exist
          const hasIfAdmin = functions.some(f => (f.modifiers || []).some(m => /ifadmin/i.test(m)));
          if (!hasIfAdmin) {
            findings.push({
              title: `[High] Transparent proxy ${name} — admin functions may not be properly restricted`,
              severity: 'high',
              skill: 'upgradability',
              contract: name,
              evidence: `Transparent proxy without ifAdmin modifier — admin/user function separation may be broken`,
              impact: 'Users may call admin functions or vice versa — proxy misconfiguration',
            });
          }
        }

        // 6. initialize() called more than once — check for re-initialization guard
        if (hasInitialize) {
          const initFuncs = functions.filter(f => /^initialize/i.test(f.name));
          for (const init of initFuncs) {
            const body = init.body || '';
            const hasReinitGuard = /initialized|_initialized|!initialized|require.*initialized/i.test(body);
            const hasModifierGuard = (init.modifiers || []).some(m => /initializer/i.test(m));
            if (!hasReinitGuard && !hasModifierGuard) {
              findings.push({
                title: `[High] initialize() can be called multiple times in ${name}`,
                severity: 'high',
                skill: 'upgradability',
                functionName: init.name,
                contract: name,
                evidence: `No re-initialization guard — initialize() can be called again after deployment`,
                impact: 'Attacker re-initializes contract, overwrites owner, changes critical parameters',
              });
            }
          }
        }

        // 7. Self-destruct in implementation — UUPS death risk
        const hasSelfDestruct = functions.some(f => /selfdestruct|suicide/i.test(f.body || f.name));
        if (hasSelfDestruct && isUpgradeable) {
          findings.push({
            title: `[Critical] Self-destruct in upgradeable contract ${name}`,
            severity: 'critical',
            skill: 'upgradability',
            contract: name,
            evidence: `Self-destruct in upgradeable implementation — can kill the proxy permanently`,
            impact: 'If implementation self-destructs, ALL proxy calls fail — funds locked forever',
          });
        }

        // 8. Delegatecall to untrusted address
        const hasDelegatecall = functions.some(f => /delegatecall/i.test(f.body || ''));
        if (hasDelegatecall && !isProxy) {
          findings.push({
            title: `[High] Delegatecall in non-proxy contract ${name}`,
            severity: 'high',
            skill: 'upgradability',
            contract: name,
            evidence: `Delegatecall in non-proxy contract — may allow storage collision or code injection`,
            impact: 'Malicious delegatecall target can overwrite owner slot — contract takeover',
          });
        }
      }
    }

    return findings;
  }
}

module.exports = new UpgradabilitySkill();
