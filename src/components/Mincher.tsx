import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Flame, Upload, Hash, AlertTriangle, Shield, Target, Globe,
  Mail, Link, Server, FileCode, Trash2, Copy, Download, Eye,
  CheckCircle2, XCircle, Loader2, ChevronDown, ChevronRight,
  Skull, Bug, Lock, Database, Zap
} from 'lucide-react'

interface IOC {
  type: 'ip' | 'domain' | 'url' | 'email' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'file_path' | 'registry' | 'cve'
  value: string
  context?: string
}

interface ThreatMatch {
  pattern: string
  name: string
  mitre: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  definition: string
  line?: number
}

interface MincherResult {
  id: string
  filename: string
  filesize: number
  filetype: string
  timestamp: Date
  hashes: {
    md5: string
    sha1: string
    sha256: string
  }
  iocs: IOC[]
  threats: ThreatMatch[]
  mitreMapping: { tactic: string; technique: string; id: string }[]
  riskScore: number
  entropy: number
  isPE: boolean
  isScript: boolean
  rawPreview: string
}

// IOC extraction patterns
const IOC_PATTERNS = {
  ip: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|info|biz|xyz|top|ru|cn|tk|ml|ga|cf|gq|pw|cc|ws|su|de|uk|fr|nl|au|br|jp|kr|in|it|es|pl|eu|ua|me|tv|name|pro|mobi|asia|xxx|club|online|site|tech|space|store|shop|app|dev|live|blog|cloud|network|systems|security|attack|malware|payload|c2|exfil)\b/gi,
  url: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  hash_md5: /\b[a-fA-F0-9]{32}\b/g,
  hash_sha1: /\b[a-fA-F0-9]{40}\b/g,
  hash_sha256: /\b[a-fA-F0-9]{64}\b/g,
  file_path: /(?:[A-Za-z]:\\|\\\\|\/)[^\s<>"{}|\\^`\[\]:*?"<>|]+/g,
  registry: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s<>"{}|\\^`\[\]]+/gi,
  cve: /CVE-\d{4}-\d{4,7}/gi,
}

// Threat patterns with MITRE mapping and definitions
const THREAT_PATTERNS: { pattern: RegExp; name: string; mitre: string; severity: ThreatMatch['severity']; definition: string }[] = [
  // PowerShell attacks
  { pattern: /powershell.*-enc|-encodedcommand/i, name: 'Encoded PowerShell', mitre: 'T1059.001', severity: 'high', definition: 'Encoded PowerShell commands are commonly used by attackers to obfuscate malicious scripts and evade detection.' },
  { pattern: /IEX\s*\(|Invoke-Expression/i, name: 'PowerShell IEX', mitre: 'T1059.001', severity: 'high', definition: 'Invoke-Expression executes arbitrary code, commonly used in fileless malware and living-off-the-land attacks.' },
  { pattern: /\bDownloadString\b|\bDownloadFile\b|\bWebClient\b/i, name: 'PowerShell Download', mitre: 'T1105', severity: 'high', definition: 'Web download functions used to retrieve additional payloads from remote servers.' },
  { pattern: /bypass.*executionpolicy|Set-ExecutionPolicy.*Bypass/i, name: 'Execution Policy Bypass', mitre: 'T1059.001', severity: 'medium', definition: 'Bypassing PowerShell execution policy allows unsigned scripts to run, a common initial access technique.' },

  // Credential access
  { pattern: /mimikatz|sekurlsa|lsadump|kerberos::list/i, name: 'Mimikatz', mitre: 'T1003.001', severity: 'critical', definition: 'Mimikatz is a credential dumping tool that extracts passwords, hashes, and Kerberos tickets from memory.' },
  { pattern: /procdump.*lsass|lsass\.exe.*dump/i, name: 'LSASS Dump', mitre: 'T1003.001', severity: 'critical', definition: 'Dumping LSASS process memory to extract credentials - a primary credential theft technique.' },
  { pattern: /hashdump|sam.*dump|ntds\.dit/i, name: 'Hash Dump', mitre: 'T1003.002', severity: 'critical', definition: 'Extraction of password hashes from SAM database or NTDS.dit for offline cracking.' },
  { pattern: /Get-Credential|ConvertTo-SecureString/i, name: 'Credential Harvesting', mitre: 'T1555', severity: 'medium', definition: 'PowerShell credential handling functions potentially used for credential theft.' },

  // Persistence
  { pattern: /schtasks.*\/create|at\s+\d+:\d+/i, name: 'Scheduled Task', mitre: 'T1053.005', severity: 'high', definition: 'Creating scheduled tasks for persistence - malware executes on schedule or at system events.' },
  { pattern: /reg\s+add.*\\Run|CurrentVersion\\Run/i, name: 'Registry Run Key', mitre: 'T1547.001', severity: 'high', definition: 'Adding registry Run keys for persistence - programs execute automatically on user login.' },
  { pattern: /sc\s+create|New-Service/i, name: 'Service Creation', mitre: 'T1543.003', severity: 'high', definition: 'Creating Windows services for persistence - services run with SYSTEM privileges.' },
  { pattern: /wmic.*process\s+call\s+create/i, name: 'WMI Execution', mitre: 'T1047', severity: 'high', definition: 'WMI process creation for execution and lateral movement.' },

  // Defense evasion
  { pattern: /base64.*decode|FromBase64String/i, name: 'Base64 Decode', mitre: 'T1140', severity: 'medium', definition: 'Base64 decoding commonly used to deobfuscate hidden payloads.' },
  { pattern: /\-w\s+hidden|\-windowstyle\s+hidden/i, name: 'Hidden Window', mitre: 'T1564.003', severity: 'medium', definition: 'Running processes with hidden windows to avoid user detection.' },
  { pattern: /Add-MpPreference.*ExclusionPath/i, name: 'Defender Exclusion', mitre: 'T1562.001', severity: 'high', definition: 'Adding Windows Defender exclusions to hide malware from scanning.' },
  { pattern: /Stop-Service.*WinDefend|sc\s+stop\s+WinDefend/i, name: 'Disable Defender', mitre: 'T1562.001', severity: 'critical', definition: 'Disabling Windows Defender service - critical defense evasion technique.' },

  // Lateral movement
  { pattern: /psexec|wmiexec|smbexec/i, name: 'Remote Execution Tool', mitre: 'T1570', severity: 'high', definition: 'Remote execution tools used for lateral movement across networks.' },
  { pattern: /Invoke-Command.*-ComputerName|Enter-PSSession/i, name: 'Remote PowerShell', mitre: 'T1021.006', severity: 'high', definition: 'Remote PowerShell sessions for lateral movement to other systems.' },
  { pattern: /net\s+use.*\\\\|New-PSDrive.*\\\\\\\\|copy.*\\\\\\\\.*\\$/i, name: 'SMB/Admin Share', mitre: 'T1021.002', severity: 'medium', definition: 'Accessing SMB shares or admin shares for lateral movement.' },

  // Discovery
  { pattern: /whoami|net\s+user|net\s+localgroup/i, name: 'Account Discovery', mitre: 'T1087', severity: 'low', definition: 'Commands to enumerate user accounts and group memberships.' },
  { pattern: /net\s+view|net\s+share|Get-NetShare/i, name: 'Network Share Discovery', mitre: 'T1135', severity: 'low', definition: 'Enumerating network shares for sensitive data or lateral movement targets.' },
  { pattern: /ipconfig|nslookup|nltest/i, name: 'Network Discovery', mitre: 'T1016', severity: 'low', definition: 'Basic network configuration and domain discovery commands.' },
  { pattern: /Get-ADUser|Get-ADComputer|Get-ADGroup/i, name: 'AD Enumeration', mitre: 'T1087.002', severity: 'medium', definition: 'Active Directory enumeration for mapping domain objects.' },

  // Exfiltration
  { pattern: /Compress-Archive|7z\s+a|rar\s+a/i, name: 'Data Compression', mitre: 'T1560', severity: 'medium', definition: 'Compressing data before exfiltration to reduce transfer size.' },
  { pattern: /certutil.*-encode|certutil.*-urlcache/i, name: 'CertUtil Abuse', mitre: 'T1105', severity: 'high', definition: 'Abusing certutil.exe for file download or data encoding - living off the land.' },
  { pattern: /bitsadmin.*\/transfer/i, name: 'BITS Transfer', mitre: 'T1197', severity: 'medium', definition: 'Using BITS for stealthy file transfers that survive reboots.' },

  // Malware indicators
  { pattern: /\.(exe|dll|bat|ps1|vbs|js)\s*$/i, name: 'Executable Extension', mitre: 'T1204.002', severity: 'low', definition: 'File with executable extension detected.' },
  { pattern: /reverse.*shell|bind.*shell|meterpreter/i, name: 'Shell/C2 Indicator', mitre: 'T1059', severity: 'critical', definition: 'Reverse shell, bind shell, or Meterpreter - critical remote access indicators.' },
  { pattern: /beacon|cobalt|empire|covenant/i, name: 'C2 Framework', mitre: 'T1071', severity: 'critical', definition: 'Commercial or open-source C2 framework indicators detected.' },
  { pattern: /ransomware|encrypt.*files|\.locked|\.encrypted/i, name: 'Ransomware Indicator', mitre: 'T1486', severity: 'critical', definition: 'Potential ransomware activity - file encryption indicators.' },

  // Web attacks
  { pattern: /\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\'.*--/i, name: 'SQL Injection', mitre: 'T1190', severity: 'high', definition: 'SQL injection attack pattern - database exploitation attempt.' },
  { pattern: /<script>|javascript:|onerror\s*=|onload\s*=/i, name: 'XSS Pattern', mitre: 'T1059.007', severity: 'medium', definition: 'Cross-site scripting (XSS) attack pattern - client-side code injection.' },
  { pattern: /\.\.\/|\.\.\\|%2e%2e/i, name: 'Path Traversal', mitre: 'T1083', severity: 'medium', definition: 'Directory traversal attempt - accessing files outside webroot.' },
]

// MITRE ATT&CK tactic mapping
const MITRE_TACTICS: { [key: string]: { tactic: string; name: string } } = {
  'T1059': { tactic: 'execution', name: 'Execution' },
  'T1059.001': { tactic: 'execution', name: 'Execution' },
  'T1059.007': { tactic: 'execution', name: 'Execution' },
  'T1047': { tactic: 'execution', name: 'Execution' },
  'T1204.002': { tactic: 'execution', name: 'Execution' },
  'T1105': { tactic: 'command-and-control', name: 'Command & Control' },
  'T1003.001': { tactic: 'credential-access', name: 'Credential Access' },
  'T1003.002': { tactic: 'credential-access', name: 'Credential Access' },
  'T1555': { tactic: 'credential-access', name: 'Credential Access' },
  'T1053.005': { tactic: 'persistence', name: 'Persistence' },
  'T1547.001': { tactic: 'persistence', name: 'Persistence' },
  'T1543.003': { tactic: 'persistence', name: 'Persistence' },
  'T1140': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1564.003': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1562.001': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1570': { tactic: 'lateral-movement', name: 'Lateral Movement' },
  'T1021.006': { tactic: 'lateral-movement', name: 'Lateral Movement' },
  'T1021.002': { tactic: 'lateral-movement', name: 'Lateral Movement' },
  'T1087': { tactic: 'discovery', name: 'Discovery' },
  'T1087.002': { tactic: 'discovery', name: 'Discovery' },
  'T1135': { tactic: 'discovery', name: 'Discovery' },
  'T1016': { tactic: 'discovery', name: 'Discovery' },
  'T1083': { tactic: 'discovery', name: 'Discovery' },
  'T1560': { tactic: 'exfiltration', name: 'Exfiltration' },
  'T1197': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1071': { tactic: 'command-and-control', name: 'Command & Control' },
  'T1486': { tactic: 'impact', name: 'Impact' },
  'T1190': { tactic: 'initial-access', name: 'Initial Access' },
}

// Calculate string entropy
function calculateEntropy(str: string): number {
  const freq: { [key: string]: number } = {}
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1
  }
  let entropy = 0
  const len = str.length
  for (const char in freq) {
    const p = freq[char] / len
    entropy -= p * Math.log2(p)
  }
  return entropy
}

// Simple MD5-like hash (for demo - use crypto.subtle for real MD5)
async function hashMD5(buffer: ArrayBuffer): Promise<string> {
  // Note: Web Crypto doesn't support MD5, so we simulate it
  // In production, use a proper MD5 library
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashSHA1(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-1', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashSHA256(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// Extract IOCs from content
function extractIOCs(content: string): IOC[] {
  const iocs: IOC[] = []
  const seen = new Set<string>()

  for (const [type, pattern] of Object.entries(IOC_PATTERNS)) {
    const matches = content.match(pattern) || []
    for (const match of matches) {
      const key = `${type}:${match.toLowerCase()}`
      if (!seen.has(key)) {
        seen.add(key)
        // Find context around the IOC
        const idx = content.indexOf(match)
        const start = Math.max(0, idx - 30)
        const end = Math.min(content.length, idx + match.length + 30)
        const context = content.slice(start, end).replace(/\n/g, ' ').trim()

        iocs.push({
          type: type as IOC['type'],
          value: match,
          context: context !== match ? `...${context}...` : undefined
        })
      }
    }
  }

  return iocs
}

// Detect threats in content
function detectThreats(content: string): ThreatMatch[] {
  const threats: ThreatMatch[] = []
  const lines = content.split('\n')

  for (const { pattern, name, mitre, severity, definition } of THREAT_PATTERNS) {
    // Check whole content
    if (pattern.test(content)) {
      // Find line number
      let lineNum: number | undefined
      for (let i = 0; i < lines.length; i++) {
        if (pattern.test(lines[i])) {
          lineNum = i + 1
          break
        }
      }

      threats.push({ pattern: pattern.source, name, mitre, severity, definition, line: lineNum })
    }
  }

  return threats
}

// Get MITRE mapping from threats
function getMitreMapping(threats: ThreatMatch[]): { tactic: string; technique: string; id: string }[] {
  const seen = new Set<string>()
  const mapping: { tactic: string; technique: string; id: string }[] = []

  for (const threat of threats) {
    if (!seen.has(threat.mitre)) {
      seen.add(threat.mitre)
      const info = MITRE_TACTICS[threat.mitre]
      if (info) {
        mapping.push({
          tactic: info.name,
          technique: threat.name,
          id: threat.mitre
        })
      }
    }
  }

  return mapping
}

// Calculate risk score
function calculateRiskScore(threats: ThreatMatch[], iocs: IOC[]): number {
  let score = 0

  for (const threat of threats) {
    switch (threat.severity) {
      case 'critical': score += 30; break
      case 'high': score += 20; break
      case 'medium': score += 10; break
      case 'low': score += 5; break
    }
  }

  // IOC scoring
  score += iocs.filter(i => i.type === 'ip').length * 5
  score += iocs.filter(i => i.type === 'domain').length * 3
  score += iocs.filter(i => i.type === 'url').length * 4
  score += iocs.filter(i => i.type.startsWith('hash')).length * 2

  return Math.min(100, score)
}

// Check if content looks like PE
function checkPE(buffer: ArrayBuffer): boolean {
  const bytes = new Uint8Array(buffer)
  return bytes[0] === 0x4D && bytes[1] === 0x5A // MZ header
}

// Check if content is a script
function checkScript(filename: string, content: string): boolean {
  const scriptExtensions = ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.py', '.sh', '.rb']
  const hasScriptExt = scriptExtensions.some(ext => filename.toLowerCase().endsWith(ext))
  const hasShebang = content.startsWith('#!') || content.startsWith('#!/')
  return hasScriptExt || hasShebang
}

function ResultCard({ result, onDelete }: { result: MincherResult; onDelete: () => void }) {
  const [expanded, setExpanded] = useState(true)
  const [showPreview, setShowPreview] = useState(false)

  const severityColor = (severity: ThreatMatch['severity']) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/20'
      case 'high': return 'text-orange-500 bg-orange-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-blue-400 bg-blue-400/20'
    }
  }

  const iocIcon = (type: IOC['type']) => {
    switch (type) {
      case 'ip': return <Server className="w-3 h-3" />
      case 'domain': return <Globe className="w-3 h-3" />
      case 'url': return <Link className="w-3 h-3" />
      case 'email': return <Mail className="w-3 h-3" />
      default: return <Hash className="w-3 h-3" />
    }
  }

  const riskColor = result.riskScore >= 70 ? 'text-red-500' : result.riskScore >= 40 ? 'text-yellow-500' : 'text-green-500'

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-null-surface/50 border border-null-border rounded-lg overflow-hidden"
    >
      {/* Header */}
      <div
        className="p-4 cursor-pointer hover:bg-null-border/30 flex items-center justify-between"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded ${result.riskScore >= 70 ? 'bg-red-500/20' : result.riskScore >= 40 ? 'bg-yellow-500/20' : 'bg-green-500/20'}`}>
            <Flame className={`w-5 h-5 ${riskColor}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-null-text">{result.filename}</span>
              {result.isPE && <span className="text-xs px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400">PE</span>}
              {result.isScript && <span className="text-xs px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400">Script</span>}
            </div>
            <div className="flex items-center gap-3 text-xs text-null-muted mt-1">
              <span>{(result.filesize / 1024).toFixed(1)} KB</span>
              <span>Risk: <span className={riskColor}>{result.riskScore}/100</span></span>
              <span>{result.threats.length} threats</span>
              <span>{result.iocs.length} IOCs</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); setShowPreview(!showPreview) }}
            className="p-1.5 rounded hover:bg-null-border/50 text-null-muted"
            title="Preview content"
          >
            <Eye className="w-4 h-4" />
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onDelete() }}
            className="p-1.5 rounded hover:bg-null-border/50 text-null-muted hover:text-red-400"
            title="Delete result"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          {expanded ? <ChevronDown className="w-4 h-4 text-null-muted" /> : <ChevronRight className="w-4 h-4 text-null-muted" />}
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-null-border"
          >
            {/* Hashes */}
            <div className="p-4 border-b border-null-border/50">
              <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                <Hash className="w-3 h-3" /> FILE HASHES
              </h4>
              <div className="space-y-1 font-mono text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-null-muted w-16">MD5:</span>
                  <span className="text-null-text">{result.hashes.md5}</span>
                  <button onClick={() => navigator.clipboard.writeText(result.hashes.md5)} className="p-1 hover:bg-null-border/50 rounded">
                    <Copy className="w-3 h-3 text-null-muted" />
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-null-muted w-16">SHA1:</span>
                  <span className="text-null-text">{result.hashes.sha1}</span>
                  <button onClick={() => navigator.clipboard.writeText(result.hashes.sha1)} className="p-1 hover:bg-null-border/50 rounded">
                    <Copy className="w-3 h-3 text-null-muted" />
                  </button>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-null-muted w-16">SHA256:</span>
                  <span className="text-null-text truncate max-w-md">{result.hashes.sha256}</span>
                  <button onClick={() => navigator.clipboard.writeText(result.hashes.sha256)} className="p-1 hover:bg-null-border/50 rounded">
                    <Copy className="w-3 h-3 text-null-muted" />
                  </button>
                </div>
                <div className="flex items-center gap-2 mt-2 text-null-muted">
                  <span>Entropy: {result.entropy.toFixed(2)}</span>
                  {result.entropy > 7 && <span className="text-yellow-500">(High - possibly packed/encrypted)</span>}
                </div>
              </div>
            </div>

            {/* Threats */}
            {result.threats.length > 0 && (
              <div className="p-4 border-b border-null-border/50">
                <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                  <AlertTriangle className="w-3 h-3" /> DETECTED THREATS ({result.threats.length})
                </h4>
                <div className="space-y-2">
                  {result.threats.map((threat, i) => (
                    <div key={i} className="p-2 rounded bg-null-bg/50 border border-null-border/50">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs px-1.5 py-0.5 rounded ${severityColor(threat.severity)}`}>
                          {threat.severity.toUpperCase()}
                        </span>
                        <span className="text-sm font-medium text-null-text">{threat.name}</span>
                        <span className="text-xs font-mono text-cyan-400">{threat.mitre}</span>
                        {threat.line && <span className="text-xs text-null-muted">Line {threat.line}</span>}
                      </div>
                      <p className="text-xs text-null-muted">{threat.definition}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE Mapping */}
            {result.mitreMapping.length > 0 && (
              <div className="p-4 border-b border-null-border/50">
                <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                  <Target className="w-3 h-3" /> MITRE ATT&CK MAPPING
                </h4>
                <div className="flex flex-wrap gap-2">
                  {result.mitreMapping.map((m, i) => (
                    <div key={i} className="px-2 py-1 rounded bg-red-500/10 border border-red-500/30 text-xs">
                      <span className="text-red-400 font-mono">{m.id}</span>
                      <span className="text-null-muted mx-1">|</span>
                      <span className="text-null-text">{m.tactic}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* IOCs */}
            {result.iocs.length > 0 && (
              <div className="p-4">
                <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                  <Database className="w-3 h-3" /> EXTRACTED IOCs ({result.iocs.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                  {result.iocs.slice(0, 20).map((ioc, i) => (
                    <div key={i} className="flex items-center gap-2 p-1.5 rounded bg-null-bg/50 text-xs">
                      <span className="text-null-muted">{iocIcon(ioc.type)}</span>
                      <span className="text-cyan-400 uppercase text-[10px] w-12">{ioc.type.replace('hash_', '')}</span>
                      <span className="text-null-text font-mono truncate flex-1" title={ioc.value}>{ioc.value}</span>
                      <button onClick={() => navigator.clipboard.writeText(ioc.value)} className="p-0.5 hover:bg-null-border/50 rounded">
                        <Copy className="w-3 h-3 text-null-muted" />
                      </button>
                    </div>
                  ))}
                </div>
                {result.iocs.length > 20 && (
                  <p className="text-xs text-null-muted mt-2">...and {result.iocs.length - 20} more IOCs</p>
                )}
              </div>
            )}

            {/* Content Preview */}
            {showPreview && (
              <div className="p-4 border-t border-null-border/50">
                <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                  <Eye className="w-3 h-3" /> CONTENT PREVIEW
                </h4>
                <pre className="p-3 rounded bg-null-bg/50 text-xs font-mono text-null-text overflow-x-auto max-h-48 whitespace-pre-wrap">
                  {result.rawPreview}
                </pre>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// Additional malicious strings for log hunting
const MALICIOUS_STRINGS = [
  // C2 and backdoor indicators
  { pattern: /beacon|callback|shell|backdoor|rootkit|trojan/i, category: 'Malware', severity: 'critical' as const },
  { pattern: /reverse.?shell|bind.?shell|nc\s+-[le]|netcat.*listen/i, category: 'Shell', severity: 'critical' as const },
  { pattern: /meterpreter|metasploit|cobaltstrike|empire|sliver/i, category: 'C2 Framework', severity: 'critical' as const },
  // Credential theft
  { pattern: /password|passwd|credential|secret|apikey|api.?key|token/i, category: 'Credential', severity: 'high' as const },
  { pattern: /\.htpasswd|shadow|sam\s+database|ntds|lsass/i, category: 'Credential Store', severity: 'critical' as const },
  // Suspicious commands
  { pattern: /curl.*\|.*sh|wget.*\|.*bash|fetch.*exec/i, category: 'Download & Execute', severity: 'critical' as const },
  { pattern: /chmod\s+[47][0-7][0-7]|chmod\s+\+x/i, category: 'Permission Change', severity: 'medium' as const },
  { pattern: /crontab|at\s+\d|systemctl.*enable|chkconfig/i, category: 'Persistence', severity: 'high' as const },
  { pattern: /iptables.*-A|ufw.*allow|firewall.*disable/i, category: 'Firewall Mod', severity: 'high' as const },
  // Encoding/obfuscation
  { pattern: /base64.*decode|eval\(|exec\(|system\(|passthru\(/i, category: 'Code Execution', severity: 'high' as const },
  { pattern: /\$\{.*\}|\$\(.*\)|`.*`/i, category: 'Shell Expansion', severity: 'medium' as const },
  { pattern: /\\x[0-9a-f]{2}|%[0-9a-f]{2}|&#x?[0-9a-f]+;/i, category: 'Encoded', severity: 'medium' as const },
  // Network suspicious
  { pattern: /0\.0\.0\.0|127\.0\.0\.1:(?!80|443|8080)|localhost:\d{4,5}/i, category: 'Suspicious Bind', severity: 'medium' as const },
  { pattern: /\.onion|tor2web|torproject/i, category: 'Tor/Darknet', severity: 'high' as const },
  { pattern: /pastebin|hastebin|ghostbin|privatebin/i, category: 'Paste Site', severity: 'medium' as const },
  // Data exfil
  { pattern: /exfil|upload.*data|send.*file|post.*\/.*\.(php|asp|jsp)/i, category: 'Exfiltration', severity: 'high' as const },
  { pattern: /dns.*txt|icmp.*tunnel|dnscat/i, category: 'Covert Channel', severity: 'critical' as const },
  // Privilege escalation
  { pattern: /sudo\s+-i|sudo\s+su|doas|su\s+-\s+root/i, category: 'Priv Esc', severity: 'high' as const },
  { pattern: /setuid|setgid|capabilities.*cap_/i, category: 'Priv Esc', severity: 'high' as const },
  // Crypto/ransomware
  { pattern: /encrypt|decrypt|cipher|aes.*key|rsa.*key|bitcoin|monero|ransom/i, category: 'Crypto/Ransom', severity: 'critical' as const },
  // Log tampering
  { pattern: /history\s*-c|unset\s+HISTFILE|rm.*\.bash_history|shred/i, category: 'Anti-Forensics', severity: 'critical' as const },
  { pattern: /auditctl.*-D|setenforce\s+0|apparmor.*disable/i, category: 'Security Disable', severity: 'critical' as const },
]

export default function Mincher() {
  const [results, setResults] = useState<MincherResult[]>([])
  const [processing, setProcessing] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  const [logInput, setLogInput] = useState('')
  const [showLogDropper, setShowLogDropper] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const processFile = useCallback(async (file: File) => {
    const buffer = await file.arrayBuffer()
    const content = await file.text()

    const [md5, sha1, sha256] = await Promise.all([
      hashMD5(buffer),
      hashSHA1(buffer),
      hashSHA256(buffer)
    ])

    const iocs = extractIOCs(content)
    const threats = detectThreats(content)
    const mitreMapping = getMitreMapping(threats)
    const riskScore = calculateRiskScore(threats, iocs)
    const entropy = calculateEntropy(content)
    const isPE = checkPE(buffer)
    const isScript = checkScript(file.name, content)

    const result: MincherResult = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      filename: file.name,
      filesize: file.size,
      filetype: file.type || 'application/octet-stream',
      timestamp: new Date(),
      hashes: { md5, sha1, sha256 },
      iocs,
      threats,
      mitreMapping,
      riskScore,
      entropy,
      isPE,
      isScript,
      rawPreview: content.slice(0, 2000) + (content.length > 2000 ? '\n\n... [truncated]' : '')
    }

    return result
  }, [])

  const handleFiles = useCallback(async (files: FileList | File[]) => {
    setProcessing(true)
    const fileArray = Array.from(files)

    try {
      const newResults = await Promise.all(fileArray.map(processFile))
      setResults(prev => [...newResults, ...prev])
    } catch (e) {
      console.error('Error processing files:', e)
    } finally {
      setProcessing(false)
    }
  }, [processFile])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
    if (e.dataTransfer.files.length > 0) {
      handleFiles(e.dataTransfer.files)
    }
  }, [handleFiles])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
  }, [])

  // Process pasted log content
  const processLogContent = useCallback(async (content: string, name: string = 'pasted-log.txt') => {
    setProcessing(true)
    try {
      const encoder = new TextEncoder()
      const buffer = encoder.encode(content).buffer

      const [md5, sha1, sha256] = await Promise.all([
        hashMD5(buffer),
        hashSHA1(buffer),
        hashSHA256(buffer)
      ])

      const iocs = extractIOCs(content)
      const threats = detectThreats(content)

      // Also check malicious strings
      const lines = content.split('\n')
      for (const { pattern, category, severity } of MALICIOUS_STRINGS) {
        for (let i = 0; i < lines.length; i++) {
          if (pattern.test(lines[i])) {
            // Map to MITRE
            const mitreMap: { [key: string]: string } = {
              'Malware': 'T1059',
              'Shell': 'T1059',
              'C2 Framework': 'T1071',
              'Credential': 'T1555',
              'Credential Store': 'T1003',
              'Download & Execute': 'T1105',
              'Permission Change': 'T1222',
              'Persistence': 'T1053',
              'Firewall Mod': 'T1562',
              'Code Execution': 'T1059',
              'Shell Expansion': 'T1059',
              'Encoded': 'T1140',
              'Suspicious Bind': 'T1571',
              'Tor/Darknet': 'T1090',
              'Paste Site': 'T1567',
              'Exfiltration': 'T1041',
              'Covert Channel': 'T1572',
              'Priv Esc': 'T1068',
              'Crypto/Ransom': 'T1486',
              'Anti-Forensics': 'T1070',
              'Security Disable': 'T1562',
            }
            const existing = threats.find(t => t.pattern === pattern.source)
            if (!existing) {
              threats.push({
                pattern: pattern.source,
                name: category,
                mitre: mitreMap[category] || 'T1059',
                severity,
                definition: `Malicious string pattern: ${category}`,
                line: i + 1
              })
            }
            break
          }
        }
      }

      const mitreMapping = getMitreMapping(threats)
      const riskScore = calculateRiskScore(threats, iocs)
      const entropy = calculateEntropy(content)

      const result: MincherResult = {
        id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        filename: name,
        filesize: content.length,
        filetype: 'text/plain',
        timestamp: new Date(),
        hashes: { md5, sha1, sha256 },
        iocs,
        threats,
        mitreMapping,
        riskScore,
        entropy,
        isPE: false,
        isScript: checkScript(name, content),
        rawPreview: content.slice(0, 2000) + (content.length > 2000 ? '\n\n... [truncated]' : '')
      }

      setResults(prev => [result, ...prev])
      setLogInput('')
      setShowLogDropper(false)
    } catch (e) {
      console.error('Error processing log:', e)
    } finally {
      setProcessing(false)
    }
  }, [])

  const deleteResult = (id: string) => {
    setResults(prev => prev.filter(r => r.id !== id))
  }

  const clearAll = () => {
    setResults([])
  }

  const exportResults = () => {
    const data = JSON.stringify(results, null, 2)
    const blob = new Blob([data], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mincher-results-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalThreats = results.reduce((sum, r) => sum + r.threats.length, 0)
  const totalIOCs = results.reduce((sum, r) => sum + r.iocs.length, 0)
  const criticalCount = results.reduce((sum, r) => sum + r.threats.filter(t => t.severity === 'critical').length, 0)

  return (
    <div className="h-full overflow-auto p-4 grid-bg">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gradient-to-br from-orange-500/20 to-red-600/20 border border-orange-500/30">
            <Flame className="w-6 h-6 text-orange-400" />
          </div>
          <div>
            <h2 className="font-display text-lg">Forensic Mincher</h2>
            <p className="text-xs text-null-muted">Drop files for automatic forensic analysis - Hashes, IOCs, Threats, MITRE</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowLogDropper(!showLogDropper)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm transition-all ${
              showLogDropper
                ? 'bg-orange-500/20 border border-orange-500/50 text-orange-400'
                : 'bg-null-border/50 text-null-muted hover:text-null-text'
            }`}
          >
            <FileCode className="w-4 h-4" />
            Paste Logs
          </button>
          {results.length > 0 && (
            <>
              <button
                onClick={exportResults}
                className="flex items-center gap-2 px-3 py-1.5 rounded bg-null-border/50 text-null-muted hover:text-null-text text-sm"
              >
                <Download className="w-4 h-4" />
                Export
              </button>
              <button
                onClick={clearAll}
                className="flex items-center gap-2 px-3 py-1.5 rounded bg-null-border/50 text-null-muted hover:text-red-400 text-sm"
              >
                <Trash2 className="w-4 h-4" />
                Clear All
              </button>
            </>
          )}
        </div>
      </div>

      {/* Log Dropper Textarea */}
      <AnimatePresence>
        {showLogDropper && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mb-4 overflow-hidden"
          >
            <div className="p-4 bg-null-surface/50 border border-orange-500/30 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-orange-400" />
                  <span className="text-sm font-medium text-null-text">Log Dropper - Paste & Hunt</span>
                </div>
                <span className="text-xs text-null-muted">Paste logs, commands, or suspicious content for IOC hunting</span>
              </div>
              <textarea
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                placeholder={`Paste logs, shell history, or suspicious content here...

Examples of what gets detected:
• IPs, domains, URLs, emails, hashes
• PowerShell attacks: IEX, DownloadString, -enc
• Credential theft: mimikatz, lsass dump, hashdump
• Persistence: schtasks, registry run keys, services
• C2/Malware: meterpreter, cobalt strike, reverse shells
• Exfiltration: curl | sh, base64 decode, certutil
• Anti-forensics: history -c, auditctl -D`}
                className="w-full h-40 p-3 bg-null-bg/50 border border-null-border rounded font-mono text-sm text-null-text placeholder:text-null-muted/50 resize-none outline-none focus:border-orange-500/50"
              />
              <div className="flex items-center justify-between mt-2">
                <div className="text-xs text-null-muted">
                  {logInput.length > 0 && <span>{logInput.length} chars | {logInput.split('\n').length} lines</span>}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setLogInput('')}
                    className="px-3 py-1.5 text-xs rounded bg-null-border/50 text-null-muted hover:text-null-text"
                  >
                    Clear
                  </button>
                  <button
                    onClick={() => logInput.trim() && processLogContent(logInput)}
                    disabled={!logInput.trim() || processing}
                    className={`px-4 py-1.5 text-xs rounded flex items-center gap-2 ${
                      logInput.trim() && !processing
                        ? 'bg-gradient-to-r from-orange-500/20 to-red-600/20 border border-orange-500/50 text-orange-400 hover:bg-orange-500/30'
                        : 'bg-null-border/30 text-null-muted cursor-not-allowed'
                    }`}
                  >
                    {processing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                    Analyze
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Stats */}
      {results.length > 0 && (
        <div className="grid grid-cols-4 gap-4 mb-4">
          <div className="p-3 rounded-lg bg-null-surface/50 border border-null-border">
            <div className="flex items-center gap-2 text-null-muted text-xs mb-1">
              <FileCode className="w-3 h-3" /> Files Analyzed
            </div>
            <div className="text-2xl font-bold text-null-text">{results.length}</div>
          </div>
          <div className="p-3 rounded-lg bg-null-surface/50 border border-null-border">
            <div className="flex items-center gap-2 text-null-muted text-xs mb-1">
              <AlertTriangle className="w-3 h-3" /> Total Threats
            </div>
            <div className="text-2xl font-bold text-yellow-400">{totalThreats}</div>
          </div>
          <div className="p-3 rounded-lg bg-null-surface/50 border border-null-border">
            <div className="flex items-center gap-2 text-null-muted text-xs mb-1">
              <Skull className="w-3 h-3" /> Critical
            </div>
            <div className="text-2xl font-bold text-red-500">{criticalCount}</div>
          </div>
          <div className="p-3 rounded-lg bg-null-surface/50 border border-null-border">
            <div className="flex items-center gap-2 text-null-muted text-xs mb-1">
              <Database className="w-3 h-3" /> IOCs Extracted
            </div>
            <div className="text-2xl font-bold text-cyan-400">{totalIOCs}</div>
          </div>
        </div>
      )}

      {/* Drop Zone */}
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
        className={`
          p-8 mb-4 border-2 border-dashed rounded-lg cursor-pointer transition-all
          flex flex-col items-center justify-center gap-3
          ${dragActive
            ? 'border-orange-500 bg-orange-500/10'
            : 'border-null-border hover:border-null-primary/50 bg-null-surface/30 hover:bg-null-surface/50'}
        `}
      >
        {processing ? (
          <>
            <Loader2 className="w-10 h-10 text-orange-400 animate-spin" />
            <p className="text-null-text">Processing files...</p>
          </>
        ) : (
          <>
            <div className="p-4 rounded-full bg-gradient-to-br from-orange-500/20 to-red-600/20">
              <Flame className="w-10 h-10 text-orange-400" />
            </div>
            <div className="text-center">
              <p className="text-null-text font-medium">Drop files into the Mincher</p>
              <p className="text-sm text-null-muted mt-1">Logs, binaries, scripts, configs - everything gets nuked forensically</p>
            </div>
            <div className="flex items-center gap-4 text-xs text-null-muted mt-2">
              <span className="flex items-center gap-1"><Hash className="w-3 h-3" /> MD5/SHA1/SHA256</span>
              <span className="flex items-center gap-1"><Bug className="w-3 h-3" /> Threat Detection</span>
              <span className="flex items-center gap-1"><Target className="w-3 h-3" /> MITRE Mapping</span>
              <span className="flex items-center gap-1"><Database className="w-3 h-3" /> IOC Extraction</span>
            </div>
          </>
        )}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={(e) => e.target.files && handleFiles(e.target.files)}
          className="hidden"
        />
      </div>

      {/* Results */}
      <div className="space-y-3">
        {results.map(result => (
          <ResultCard
            key={result.id}
            result={result}
            onDelete={() => deleteResult(result.id)}
          />
        ))}
      </div>

      {/* Empty state */}
      {results.length === 0 && !processing && (
        <div className="text-center py-12 text-null-muted">
          <Flame className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No files analyzed yet</p>
          <p className="text-sm mt-1">Drop files above to start forensic analysis</p>
        </div>
      )}
    </div>
  )
}
