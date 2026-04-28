/**
 * MCP (Model Context Protocol) Integration Module
 * Connects Codex agents to external intelligence sources:
 * - SWC Registry: Known Solidity vulnerability patterns
 * - DeFiLlama: Protocol TVL, exploit history, protocol context
 * - OWASP: Web vulnerability patterns
 * - CVE Database: Known vulnerabilities in detected technologies
 */

const https = require('https');
const http = require('http');

class MCPClient {
  constructor(config = {}) {
    this.servers = config.servers || [];
    this.cache = new Map();
    this.cacheTTL = config.cacheTTL || 3600000; // 1 hour
  }

  async query(serverName, query) {
    const cacheKey = `${serverName}:${query}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.data;
    }

    const server = this.servers.find(s => s.name === serverName);
    if (!server) {
      return { error: `MCP server "${serverName}" not configured` };
    }

    try {
      const data = await this._fetch(server.url, query);
      this.cache.set(cacheKey, { data, timestamp: Date.now() });
      return data;
    } catch (err) {
      return { error: `MCP query failed: ${err.message}` };
    }
  }

  _fetch(url, query) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: `${urlObj.pathname}?q=${encodeURIComponent(query)}`,
        method: 'GET',
        timeout: 10000,
        headers: { 'Accept': 'application/json' },
      };

      const client = urlObj.protocol === 'https:' ? https : http;
      const req = client.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(body)); }
          catch { resolve({ raw: body }); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      req.end();
    });
  }
}

// SWC Registry — Solidity vulnerability patterns
class SWCRegistry {
  constructor() {
    this.patterns = {
      'SWC-101': { name: 'Integer Overflow and Underflow', severity: 'high', url: 'https://swcregistry.io/docs/SWC-101' },
      'SWC-102': { name: 'Outdated Compiler Version', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-102' },
      'SWC-103': { name: 'Floating Pragma', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-103' },
      'SWC-104': { name: 'Unchecked Return Value', severity: 'high', url: 'https://swcregistry.io/docs/SWC-104' },
      'SWC-105': { name: 'Unprotected Ether Withdrawal', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-105' },
      'SWC-106': { name: 'Unprotected SELFDESTRUCT Instruction', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-106' },
      'SWC-107': { name: 'Reentrancy', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-107' },
      'SWC-108': { name: 'State Variable Default Visibility', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-108' },
      'SWC-109': { name: 'Uninitialized Storage Pointer', severity: 'high', url: 'https://swcregistry.io/docs/SWC-109' },
      'SWC-110': { name: 'Assert Violation', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-110' },
      'SWC-111': { name: 'Use of Deprecated Solidity Functions', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-111' },
      'SWC-112': { name: 'Delegatecall to Untrusted Callee', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-112' },
      'SWC-113': { name: 'DoS with Failed Call', severity: 'high', url: 'https://swcregistry.io/docs/SWC-113' },
      'SWC-114': { name: 'Transaction Order Dependence', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-114' },
      'SWC-115': { name: 'Authorization through tx.origin', severity: 'high', url: 'https://swcregistry.io/docs/SWC-115' },
      'SWC-116': { name: 'Block values as a proxy for time', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-116' },
      'SWC-117': { name: 'Signature Malleability', severity: 'high', url: 'https://swcregistry.io/docs/SWC-117' },
      'SWC-118': { name: 'Shadowing State Variables', severity: 'high', url: 'https://swcregistry.io/docs/SWC-118' },
      'SWC-119': { name: 'Shadowing Assembly Local Variable', severity: 'low', url: 'https://swcregistry.io/docs/SWC-119' },
      'SWC-120': { name: 'Weak Randomness', severity: 'high', url: 'https://swcregistry.io/docs/SWC-120' },
      'SWC-121': { name: 'Improper Protection of Homomorphic Gas Incentive', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-121' },
      'SWC-122': { name: 'Lack of Proper Signature Verification', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-122' },
      'SWC-123': { name: 'Requirement Violation', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-123' },
      'SWC-124': { name: 'Write to Arbitrary Storage Location', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-124' },
      'SWC-125': { name: 'Incorrect Inheritance Order', severity: 'high', url: 'https://swcregistry.io/docs/SWC-125' },
      'SWC-126': { name: 'Insufficient Gas Griefing', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-126' },
      'SWC-127': { name: 'Arbitrary Jump with Function Type Variable', severity: 'critical', url: 'https://swcregistry.io/docs/SWC-127' },
      'SWC-128': { name: 'DoS with Block Gas Limit', severity: 'high', url: 'https://swcregistry.io/docs/SWC-128' },
      'SWC-129': { name: 'Race Condition / Incorrect Ordering of Library Calls', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-129' },
      'SWC-130': { name: 'Right-To-Left-Override control character', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-130' },
      'SWC-131': { name: 'Presence of unused variables', severity: 'low', url: 'https://swcregistry.io/docs/SWC-131' },
      'SWC-132': { name: 'Unexpected Ether Balance', severity: 'high', url: 'https://swcregistry.io/docs/SWC-132' },
      'SWC-133': { name: 'Hash Collisions With Multiple Variable Packing', severity: 'high', url: 'https://swcregistry.io/docs/SWC-133' },
      'SWC-134': { name: 'Message Call With External Data', severity: 'medium', url: 'https://swcregistry.io/docs/SWC-134' },
      'SWC-135': { name: 'Code With No Effects', severity: 'low', url: 'https://swcregistry.io/docs/SWC-135' },
      'SWC-136': { name: 'Unencrypted Private Data On-Chain', severity: 'high', url: 'https://swcregistry.io/docs/SWC-136' },
      'SWC-137': { name: 'Incorrect Constructor Name', severity: 'high', url: 'https://swcregistry.io/docs/SWC-137' },
      'SWC-138': { name: 'Incorrect Ammounts in Burn/Mint', severity: 'high', url: 'https://swcregistry.io/docs/SWC-138' },
    };
  }

  lookup(findingName) {
    const results = [];
    for (const [id, pattern] of Object.entries(this.patterns)) {
      if (pattern.name.toLowerCase().includes(findingName.toLowerCase()) ||
          id.toLowerCase().includes(findingName.toLowerCase())) {
        results.push({ id, ...pattern });
      }
    }
    return results;
  }

  getBySkill(skillName) {
    const mapping = {
      'reentrancy': ['SWC-107'],
      'overflow': ['SWC-101'],
      'unchecked-returns': ['SWC-104'],
      'access-control': ['SWC-105', 'SWC-115'],
      'self-destruct': ['SWC-106'],
      'delegatecall': ['SWC-112'],
      'storage-pointer': ['SWC-109'],
      'shadowing': ['SWC-118'],
      'pragma-bugs': ['SWC-102', 'SWC-103'],
      'signature-malleability': ['SWC-117'],
      'timestamp-dependence': ['SWC-116'],
      'gas-griefing': ['SWC-126', 'SWC-128'],
      'inheritance-order': ['SWC-125'],
      'front-running': ['SWC-114'],
      'pool-freeze': ['SWC-113', 'SWC-128'],
    };
    const ids = mapping[skillName] || [];
    return ids.map(id => ({ id, ...this.patterns[id] })).filter(Boolean);
  }
}

// DeFiLlama — Protocol context for DeFi audits
class DeFiLlamaClient {
  constructor() {
    this.baseUrl = 'https://api.llama.fi';
    this.cache = new Map();
  }

  async getProtocol(name) {
    const cacheKey = `protocol:${name}`;
    if (this.cache.has(cacheKey)) return this.cache.get(cacheKey);

    try {
      const data = await this._fetch(`${this.baseUrl}/protocol/${name}`);
      this.cache.set(cacheKey, data);
      return data;
    } catch { return null; }
  }

  async getTVL(protocolId) {
    try {
      return await this._fetch(`${this.baseUrl}/tvl/${protocolId}`);
    } catch { return null; }
  }

  async getExploits() {
    try {
      return await this._fetch(`${this.baseUrl}/exploits`);
    } catch { return []; }
  }

  _fetch(url) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      https.get({
        hostname: urlObj.hostname,
        path: urlObj.pathname,
        timeout: 10000,
        headers: { 'Accept': 'application/json' },
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(body)); }
          catch { resolve(null); }
        });
      }).on('error', reject);
    });
  }
}

module.exports = { MCPClient, SWCRegistry, DeFiLlamaClient };
