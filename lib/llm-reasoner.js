/**
 * LLM Reasoning Engine — GPT-5.4 Pro with xhigh reasoning effort
 * Provides deep vulnerability reasoning, exploit path analysis, and audit synthesis.
 * Requires OPENAI_API_KEY environment variable.
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

class LLMReasoner {
  constructor(opts = {}) {
    this.apiKey = opts.apiKey || process.env.OPENAI_API_KEY;
    this.model = opts.model || 'gpt-4o';  // Will use gpt-5.4-pro when available
    this.reasoningEffort = opts.reasoningEffort || 'high';
    this.maxTokens = opts.maxTokens || 16000;
    this.baseUrl = opts.baseUrl || 'https://api.openai.com/v1';
    this.enabled = !!this.apiKey;
    this.conversationHistory = [];
    this.auditContext = '';

    if (!this.enabled) {
      console.log('  ℹ️  LLM reasoning disabled — set OPENAI_API_KEY to enable GPT-5.4 xhigh analysis');
    }
  }

  /**
   * Initialize audit context with contract source code
   */
  initAuditContext(contracts, findings) {
    const contractSummaries = contracts.map(f => {
      const cList = (f.contracts || []).map(c => {
        const funcs = (c.functions || []).map(fn => `${fn.name}(${(fn.params || []).join(',')})${fn.visibility ? ' ' + fn.visibility : ''}${fn.stateMutability ? ' ' + fn.stateMutability : ''}`).join(', ');
        const vars = (c.stateVars || []).map(v => `${v.type} ${v.name}`).join(', ');
        return `Contract: ${c.name}\n  State: ${vars || 'none'}\n  Functions: ${funcs || 'none'}`;
      }).join('\n\n');
      return `File: ${f.file}\n${cList}`;
    }).join('\n---\n');

    const findingSummaries = findings.map(f =>
      `[${f.severity.toUpperCase()}] ${f.title} — ${f.evidence || 'no evidence'}`
    ).join('\n');

    this.auditContext = `# Smart Contract Audit Target\n\n${contractSummaries}\n\n# Static Analysis Findings So Far\n\n${findingSummaries || 'None yet'}`;
  }

  /**
   * Deep reasoning on a specific finding — validate, escalate, or dismiss
   */
  async reasonAboutFinding(finding) {
    if (!this.enabled) return { validated: true, reasoning: 'LLM disabled — static analysis only', escalated: false };

    const prompt = `You are a world-class smart contract auditor. Analyze this finding and determine if it's a true positive, false positive, or needs escalation.

${this.auditContext}

FINDING TO ANALYZE:
Severity: ${finding.severity}
Title: ${finding.title}
Evidence: ${finding.evidence || 'N/A'}
Impact: ${finding.impact || 'N/A'}
Function: ${finding.functionName || 'N/A'}
Skill: ${finding.skill || 'N/A'}

Respond in this exact JSON format:
{
  "verdict": "true_positive" | "false_positive" | "needs_escalation",
  "confidence": 0.0-1.0,
  "reasoning": "detailed technical reasoning for your verdict",
  "exploit_scenario": "concrete exploit scenario if true positive, empty string if false positive",
  "suggested_severity": "critical" | "high" | "medium" | "low" | "info",
  "cross_references": ["list of other vulnerability patterns this relates to"]
}`;

    return this._callLLM(prompt, finding);
  }

  /**
   * Generate a full audit synthesis — combines all findings into a coherent narrative
   */
  async synthesizeAudit(findings, contracts) {
    if (!this.enabled) return null;

    const prompt = `You are a senior smart contract security researcher. Synthesize the following audit findings into a comprehensive report.

${this.auditContext}

ALL FINDINGS:
${findings.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n   Evidence: ${f.evidence || 'N/A'}\n   Impact: ${f.impact || 'N/A'}`).join('\n\n')}

Provide:
1. EXECUTIVE SUMMARY — Overall risk assessment in 2-3 sentences
2. CRITICAL PATH — The most dangerous combination of vulnerabilities that could lead to fund loss
3. ATTACK TREES — For each critical/high finding, describe the step-by-step exploit path
4. RECOMMENDATIONS — Prioritized list of fixes, ordered by risk reduction impact
5. INVARIANTS — Key invariants that should hold but may be breakable
6. MISSED AREAS — What should be manually reviewed that automated tools may have missed`;

    return this._callLLM(prompt);
  }

  /**
   * Deep analysis of a specific contract function
   */
  async analyzeFunction(contractName, functionName, sourceCode) {
    if (!this.enabled) return null;

    const prompt = `You are a smart contract security expert. Perform deep security analysis of this function.

Contract: ${contractName}
Function: ${functionName}

Source Code:
\`\`\`solidity
${sourceCode}
\`\`\`

Analyze for:
1. Reentrancy vectors (external calls before state updates)
2. Access control gaps (missing or bypassable modifiers)
3. Integer overflow/underflow
4. Front-running / MEV vulnerability
5. Logic errors (off-by-one, wrong comparison, missing checks)
6. State manipulation (flash loan, oracle, donation attacks)
7. Gas griefing or DOS vectors

For each vulnerability found, respond in JSON:
{
  "vulnerabilities": [
    {
      "type": "vulnerability_category",
      "severity": "critical|high|medium|low",
      "title": "descriptive title",
      "evidence": "exact line(s) and reasoning",
      "exploit_scenario": "how to exploit",
      "remediation": "how to fix"
    }
  ]
}`;

    return this._callLLM(prompt);
  }

  /**
   * Cross-contract reasoning — analyze interactions between contracts
   */
  async reasonAboutCrossContract(findings, contractNames) {
    if (!this.enabled) return null;

    const prompt = `You are analyzing a multi-contract DeFi protocol. Consider how these findings interact across contracts.

Contracts in scope: ${contractNames.join(', ')}

${this.auditContext}

CROSS-CONTRACT FINDINGS:
${findings.map(f => `[${f.severity}] ${f.title} — ${f.evidence || ''}`).join('\n')}

Identify:
1. COMPOUND VULNERABILITIES — Where two medium findings combine into a critical exploit
2. CASCADING FAILURES — Where one exploit enables another in a different contract
3. COMPOSABILITY RISKS — How external protocols could trigger these issues
4. RECOMMENDED MITIGATION SEQUENCE — Which fixes break the most exploit chains`;

    return this._callLLM(prompt);
  }

  /**
   * Generate exploit PoC with LLM reasoning
   */
  async generateExploitPoC(finding, contractSource) {
    if (!this.enabled) return null;

    const prompt = `Generate a Foundry test contract (Solidity) that proves this vulnerability is exploitable.

VULNERABILITY:
[${finding.severity}] ${finding.title}
Evidence: ${finding.evidence || 'N/A'}
Impact: ${finding.impact || 'N/A'}

CONTRACT SOURCE:
\`\`\`solidity
${contractSource.substring(0, 8000)}
\`\`\`

Generate a complete Foundry test (.t.sol) that:
1. Sets up the exploit scenario
2. Executes the attack
3. Asserts the exploit succeeded (e.g., balance changed, access gained)
4. Includes comments explaining each step

Output ONLY the Solidity code, no explanations outside the code.`;

    return this._callLLM(prompt);
  }

  async _callLLM(prompt, originalFinding = null) {
    if (!this.apiKey) {
      return { validated: true, reasoning: 'No API key — static analysis only', escalated: false };
    }

    try {
      const messages = [
        {
          role: 'system',
          content: `You are an elite smart contract security auditor with deep expertise in DeFi protocols, EVM internals, and exploit development. You think methodically and never make unfounded claims. You provide concrete evidence and exploit scenarios. You use maximum reasoning effort (xhigh) for complex vulnerability analysis.`,
        },
        { role: 'user', content: prompt },
      ];

      const body = {
        model: this.model,
        messages,
        max_tokens: this.maxTokens,
        temperature: 0.1,  // Low temperature for precise security analysis
      };

      // Add reasoning effort for o1/o3 models
      if (this.model.includes('o1') || this.model.includes('o3') || this.model.includes('5.4')) {
        body.reasoning_effort = this.reasoningEffort;
        delete body.temperature;  // Reasoning models don't use temperature
      }

      const resp = await axios.post(`${this.baseUrl}/chat/completions`, body, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 120000,
      });

      const content = resp.data?.choices?.[0]?.message?.content || '';

      // Try to parse JSON from response
      try {
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          if (originalFinding) {
            return {
              ...parsed,
              validated: parsed.verdict !== 'false_positive',
              escalated: parsed.verdict === 'needs_escalation',
              originalFinding,
            };
          }
          return parsed;
        }
      } catch {}

      // Return raw content if not JSON
      if (originalFinding) {
        return {
          validated: true,
          reasoning: content,
          escalated: false,
          originalFinding,
        };
      }
      return { synthesis: content };

    } catch (err) {
      const msg = err.response?.data?.error?.message || err.message;
      console.log(`  ⚠️  LLM error: ${msg}`);
      if (originalFinding) {
        return { validated: true, reasoning: `LLM unavailable: ${msg}`, escalated: false, originalFinding };
      }
      return null;
    }
  }

  isEnabled() {
    return this.enabled;
  }

  getModel() {
    return this.model;
  }
}

module.exports = LLMReasoner;
