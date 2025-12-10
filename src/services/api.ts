// forensic.love - Standalone Security Analysis Platform
// Uses OpenRouter.ai with x-ai/grok-4.1-fast for AI agents

const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions'
const OPENROUTER_MODEL = 'x-ai/grok-4.1-fast'

// Get API key from localStorage or environment
export function getApiKey(): string | null {
  return localStorage.getItem('openrouter_api_key')
}

export function setApiKey(key: string): void {
  localStorage.setItem('openrouter_api_key', key)
}

export function hasApiKey(): boolean {
  return !!getApiKey()
}

// Agent system prompts for specialized security analysis
const AGENT_PROMPTS: Record<string, string> = {
  analyst: `You are ANALYST, an expert cybersecurity analyst AI agent specializing in:
- Log analysis and correlation
- Alert triage and severity scoring
- IOC extraction from unstructured data
- Threat pattern recognition
- Actionable security recommendations

Always provide structured analysis with clear severity ratings and recommended next steps.`,

  hunter: `You are HUNTER, an expert threat hunting AI agent specializing in:
- Hypothesis-driven threat hunting
- MITRE ATT&CK technique mapping
- Sigma/YARA rule generation
- APT TTP identification
- Proactive threat detection

Always map findings to MITRE ATT&CK techniques and provide detection rules when possible.`,

  forensic: `You are FORENSIC, an expert digital forensics AI agent specializing in:
- Evidence analysis and chain of custody
- Timeline reconstruction
- Memory and disk artifact analysis
- Network forensics
- Court-admissible documentation

Always maintain forensic rigor and document chain of custody considerations.`,

  coder: `You are CODER, an expert security code analysis AI agent specializing in:
- Vulnerability detection (OWASP, CWE)
- Malware pattern identification
- Code deobfuscation
- Secret scanning
- Secure code review

Always reference specific CWE/OWASP categories and provide remediation guidance.`,

  cerebro: `You are CEREBRO, an advanced AI security orchestrator specializing in:
- Multi-stage attack analysis
- Cross-domain threat correlation
- Automated incident response recommendations
- Risk scoring and prioritization
- Executive-level security briefings

Provide comprehensive, actionable intelligence synthesis.`,

  macforensics: `You are a macOS forensics expert specializing in:
- Apple File System (APFS) analysis
- macOS artifact extraction and interpretation
- Unified logging analysis
- Keychain and credential analysis
- Time Machine backup forensics
- Application sandbox analysis

Provide detailed forensic analysis with chain of custody considerations.`
}

// Demo responses when no API key is configured
const DEMO_RESPONSES: Record<string, string[]> = {
  analyst: [
    "**Severity: HIGH**\n\nBased on my analysis, this appears to be a sophisticated APT campaign targeting critical infrastructure.\n\n**IOCs Identified:**\n- Suspicious outbound connections to 185.234.xx.xx\n- Modified registry keys in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n\n**Recommended Actions:**\n1. Isolate affected endpoints\n2. Block identified C2 IPs at firewall\n3. Initiate memory acquisition for further analysis",
    "**Alert Triage Complete**\n\nI've identified several indicators of compromise (IOCs) including suspicious network connections to known C2 servers.\n\n**MITRE ATT&CK Mapping:**\n- T1071.001 - Application Layer Protocol: Web Protocols\n- T1059.001 - PowerShell\n\n**Next Steps:**\n- Correlate with EDR telemetry\n- Check for lateral movement indicators",
  ],
  hunter: [
    "**Threat Hunt Results**\n\nThe malware uses process hollowing and DLL sideloading techniques to evade detection.\n\n**MITRE ATT&CK Techniques:**\n- T1055.012 - Process Hollowing\n- T1574.002 - DLL Side-Loading\n\n**Sigma Rule Generated:**\n```yaml\ntitle: Suspicious Process Hollowing\nstatus: experimental\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    ParentImage|endswith: '\\\\explorer.exe'\n    Image|endswith: '\\\\cmd.exe'\n  condition: selection\n```",
    "**Hunt Hypothesis Validated**\n\nEvidence of lateral movement detected via PsExec and WMI.\n\n**Techniques Identified:**\n- T1021.002 - SMB/Windows Admin Shares\n- T1047 - WMI\n- T1003.001 - LSASS Memory\n\n**Detection Opportunities:**\n- Monitor for 4624/4625 events with LogonType 3\n- Alert on service installations from remote hosts",
  ],
  forensic: [
    "**Forensic Timeline Reconstruction**\n\nThe forensic timeline shows initial access occurred via spearphishing at 14:32 UTC.\n\n**Attack Chain:**\n1. **Initial Access** (14:32 UTC) - Malicious document opened\n2. **Execution** (14:33 UTC) - PowerShell spawned from Word\n3. **Persistence** (14:35 UTC) - Scheduled task created\n4. **Discovery** (14:40 UTC) - Network enumeration commands\n5. **Exfiltration** (15:12 UTC) - Data staged and transmitted\n\n**Evidence Integrity:** SHA256 hashes documented for all artifacts",
    "**Memory Analysis Report**\n\nMemory analysis reveals injected shellcode in several system processes.\n\n**Findings:**\n- Suspicious memory regions in svchost.exe (PID 1234)\n- Cobalt Strike beacon signature detected\n- Credentials extracted from LSASS\n\n**Chain of Custody:** Evidence acquired at 2024-01-15 09:23:45 UTC\nHash: SHA256:a1b2c3d4...",
  ],
  coder: [
    "**Vulnerability Analysis**\n\n**Critical Finding: SQL Injection (CWE-89)**\n\n```python\n# Vulnerable code at line 45\nquery = f\"SELECT * FROM users WHERE id = {user_input}\"\n```\n\n**Risk:** High - Direct user input concatenation allows arbitrary SQL execution\n\n**Remediation:**\n```python\n# Use parameterized queries\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_input,))\n```\n\n**OWASP Category:** A03:2021 - Injection",
    "**Code Security Review**\n\n**Findings:**\n1. **Hardcoded Credentials** (CWE-798) - Line 23\n2. **Path Traversal** (CWE-22) - Line 67\n3. **XSS Vulnerability** (CWE-79) - Line 112\n\n**Severity Distribution:**\n- Critical: 1\n- High: 2\n- Medium: 3\n\n**Recommendation:** Implement input validation and use security linters in CI/CD",
  ],
  general: [
    "I'm analyzing the data you provided. This appears to be a significant security incident.\n\nBased on MITRE ATT&CK framework mapping, this attack uses techniques T1566, T1055, and T1003.\n\nI recommend immediate containment actions: isolate affected systems and revoke compromised credentials.",
    "**Analysis Complete**\n\nKey findings indicate a multi-stage intrusion with the following characteristics:\n- Initial access via phishing\n- Privilege escalation through local exploit\n- Lateral movement using valid credentials\n\n**Priority Actions:**\n1. Reset compromised accounts\n2. Deploy additional monitoring\n3. Conduct threat hunt for similar TTPs",
  ],
}

function getDemoResponse(agentId: string): string {
  const responses = DEMO_RESPONSES[agentId] || DEMO_RESPONSES.general
  return responses[Math.floor(Math.random() * responses.length)]
}

interface ChatResponse {
  response: string
  timestamp: string
  agentId: string
}

export async function sendAgentChat(
  agentId: string,
  message: string,
  context?: string
): Promise<ChatResponse> {
  const apiKey = getApiKey()

  // Demo mode when no API key
  if (!apiKey) {
    await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 1200))
    return {
      response: getDemoResponse(agentId),
      timestamp: new Date().toISOString(),
      agentId,
    }
  }

  // Get system prompt for this agent
  const systemPrompt = AGENT_PROMPTS[agentId] || AGENT_PROMPTS.analyst

  // Build messages array
  const messages = [
    { role: 'system', content: systemPrompt },
  ]

  if (context) {
    messages.push({ role: 'user', content: `Previous context:\n${context}` })
  }

  messages.push({ role: 'user', content: message })

  // Call OpenRouter API with Grok
  const res = await fetch(OPENROUTER_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
      'HTTP-Referer': window.location.origin,
      'X-Title': 'forensic.love'
    },
    body: JSON.stringify({
      model: OPENROUTER_MODEL,
      messages,
      temperature: 0.7,
      max_tokens: 2048,
    }),
  })

  if (!res.ok) {
    const error = await res.json().catch(() => ({}))
    throw new Error(error.error?.message || `API error: ${res.status}`)
  }

  const data = await res.json()

  return {
    response: data.choices[0]?.message?.content || 'No response generated',
    timestamp: new Date().toISOString(),
    agentId,
  }
}

export async function checkApiConnection(): Promise<boolean> {
  const apiKey = getApiKey()
  if (!apiKey) return false

  try {
    const res = await fetch('https://openrouter.ai/api/v1/models', {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
      },
      signal: AbortSignal.timeout(5000)
    })
    return res.ok
  } catch {
    return false
  }
}

// Export constants for components
export const DEMO_MODE = !hasApiKey()
export { OPENROUTER_MODEL }
