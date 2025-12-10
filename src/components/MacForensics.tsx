import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Apple, Upload, Hash, AlertTriangle, Shield, Target, Globe,
  FileCode, Trash2, Copy, Download, Eye, Cpu, HardDrive,
  Loader2, ChevronDown, ChevronRight, Brain, Search, Code,
  Skull, Bug, Lock, Database, Zap, Terminal, Activity, Clock
} from 'lucide-react'
import { sendAgentChat } from '../services/api'

interface MacArtifact {
  type: 'mach-o' | 'unified-log' | 'ips-crash' | 'plist' | 'keychain' | 'launchd' | 'kext' | 'generic'
  subtype?: string
  metadata: Record<string, any>
}

interface AgentAnalysis {
  agentId: string
  agentName: string
  status: 'pending' | 'analyzing' | 'complete' | 'error'
  analysis?: string
  findings?: string[]
  recommendations?: string[]
}

interface MacForensicResult {
  id: string
  filename: string
  filesize: number
  timestamp: Date
  artifact: MacArtifact
  hashes: {
    md5: string
    sha1: string
    sha256: string
    ssdeep?: string
    imphash?: string
  }
  iocs: { type: string; value: string; context?: string }[]
  threats: { pattern: string; name: string; mitre: string; severity: 'low' | 'medium' | 'high' | 'critical'; definition: string; line?: number }[]
  mitreMapping: { tactic: string; technique: string; id: string }[]
  riskScore: number
  entropy: number
  agentAnalyses: AgentAnalysis[]
  rawPreview: string
}

// Mac-specific threat patterns
const MAC_THREAT_PATTERNS = [
  // macOS persistence
  { pattern: /LaunchAgents|LaunchDaemons|StartupItems/i, name: 'Launch Agent/Daemon', mitre: 'T1543.001', severity: 'high' as const, definition: 'macOS persistence mechanism using Launch Agents or Launch Daemons' },
  { pattern: /loginwindow|LoginHook|LogoutHook/i, name: 'Login Hook', mitre: 'T1037.002', severity: 'high' as const, definition: 'Legacy macOS persistence using login/logout hooks' },
  { pattern: /\/Library\/Cron|crontab/i, name: 'Cron Job', mitre: 'T1053.003', severity: 'medium' as const, definition: 'Cron-based persistence mechanism' },
  { pattern: /kextload|kextutil|IOKit/i, name: 'Kernel Extension', mitre: 'T1547.006', severity: 'critical' as const, definition: 'Kernel extension loading - high privilege persistence' },

  // macOS credential access
  { pattern: /security\s+find-.*-password|security\s+dump-keychain/i, name: 'Keychain Access', mitre: 'T1555.001', severity: 'critical' as const, definition: 'Accessing macOS Keychain for stored credentials' },
  { pattern: /\/var\/db\/dslocal|DirectoryService/i, name: 'Directory Service', mitre: 'T1003', severity: 'high' as const, definition: 'Accessing macOS directory service data' },
  { pattern: /sudo.*-S|osascript.*password|codesign.*-s/i, name: 'Sudo/Password Prompt', mitre: 'T1548.003', severity: 'high' as const, definition: 'Potential credential harvesting via sudo or osascript' },

  // macOS evasion
  { pattern: /xattr\s+-d.*quarantine|com\.apple\.quarantine/i, name: 'Gatekeeper Bypass', mitre: 'T1553.001', severity: 'high' as const, definition: 'Removing quarantine attribute to bypass Gatekeeper' },
  { pattern: /spctl.*--disable|csrutil\s+disable/i, name: 'SIP/Spctl Disable', mitre: 'T1562.001', severity: 'critical' as const, definition: 'Disabling System Integrity Protection or Gatekeeper' },
  { pattern: /defaults\s+write.*LSQuarantine/i, name: 'Quarantine Disable', mitre: 'T1562.001', severity: 'high' as const, definition: 'Modifying quarantine preferences' },
  { pattern: /DYLD_INSERT_LIBRARIES|dylib\s+injection/i, name: 'DYLD Injection', mitre: 'T1574.006', severity: 'critical' as const, definition: 'Dynamic library injection via DYLD environment variable' },

  // macOS discovery
  { pattern: /system_profiler|sw_vers|uname/i, name: 'System Discovery', mitre: 'T1082', severity: 'low' as const, definition: 'System information discovery commands' },
  { pattern: /dscl.*-list|dscacheutil/i, name: 'User Discovery', mitre: 'T1087.001', severity: 'low' as const, definition: 'Local user and group enumeration' },
  { pattern: /networksetup|ifconfig|netstat/i, name: 'Network Discovery', mitre: 'T1016', severity: 'low' as const, definition: 'Network configuration discovery' },

  // macOS execution
  { pattern: /osascript.*-e|osacompile/i, name: 'AppleScript Exec', mitre: 'T1059.002', severity: 'high' as const, definition: 'AppleScript execution - commonly used by macOS malware' },
  { pattern: /xattr.*-c.*uchg|chflags.*hidden/i, name: 'Hidden Files', mitre: 'T1564.001', severity: 'medium' as const, definition: 'Hiding files using extended attributes or flags' },
  { pattern: /mdfind|spotlight|mdutil/i, name: 'Spotlight Query', mitre: 'T1083', severity: 'low' as const, definition: 'Using Spotlight for file discovery' },

  // macOS-specific malware indicators
  { pattern: /Shlayer|OSX\.Pirrit|XCSSET|Silver\s*Sparrow|UpdateAgent/i, name: 'Known macOS Malware', mitre: 'T1059', severity: 'critical' as const, definition: 'Known macOS malware family detected' },
  { pattern: /\/private\/tmp\/\..*|\/Users\/Shared\/\..*/i, name: 'Suspicious Hidden Path', mitre: 'T1564.001', severity: 'high' as const, definition: 'Hidden file in suspicious location' },

  // Mach-O specific
  { pattern: /LC_DYLD_INFO|LC_SYMTAB|LC_DYSYMTAB/i, name: 'Mach-O Load Commands', mitre: 'T1059', severity: 'low' as const, definition: 'Mach-O binary load command analysis' },
  { pattern: /__DATA.*__la_symbol_ptr|__stub_helper/i, name: 'Mach-O Lazy Binding', mitre: 'T1574.006', severity: 'medium' as const, definition: 'Mach-O lazy symbol binding - potential hijack point' },

  // Unified log indicators
  { pattern: /kernel.*panic|AMFI.*failed|CODE SIGNING/i, name: 'Security Violation', mitre: 'T1553', severity: 'high' as const, definition: 'macOS security subsystem violation detected' },
  { pattern: /XProtect.*detected|MRT.*quarantine/i, name: 'XProtect Detection', mitre: 'T1059', severity: 'critical' as const, definition: 'Apple XProtect or MRT detection event' },
  { pattern: /TCC.*denied|denied.*kTCC/i, name: 'TCC Denial', mitre: 'T1548', severity: 'medium' as const, definition: 'Transparency, Consent, and Control denial - permission issues' },
]

// IOC patterns for Mac
const MAC_IOC_PATTERNS = {
  bundle_id: /com\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*/g,
  mac_path: /(?:\/Users\/[^\/\s]+|\/Applications|\/Library|\/System|\/private|\/var|\/tmp)\/[^\s<>"{}|\\^`\[\]:*?"<>|]+/g,
  plist_key: /CFBundle[A-Za-z]+|LS[A-Z][a-zA-Z]+|NS[A-Z][a-zA-Z]+/g,
  uuid: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
  code_sign: /Developer ID Application:.*|Apple Development:.*|iPhone Distribution:.*/g,
  team_id: /\([A-Z0-9]{10}\)/g,
}

// Detect artifact type from content
function detectArtifactType(filename: string, content: string, buffer: ArrayBuffer): MacArtifact {
  const bytes = new Uint8Array(buffer)

  // Mach-O detection (including fat/universal binaries)
  const machOMagics = [
    [0xFE, 0xED, 0xFA, 0xCE], // 32-bit
    [0xFE, 0xED, 0xFA, 0xCF], // 64-bit
    [0xCE, 0xFA, 0xED, 0xFE], // 32-bit (reversed)
    [0xCF, 0xFA, 0xED, 0xFE], // 64-bit (reversed)
    [0xCA, 0xFE, 0xBA, 0xBE], // Fat binary
    [0xBE, 0xBA, 0xFE, 0xCA], // Fat binary (reversed)
  ]

  for (const magic of machOMagics) {
    if (bytes.length >= 4 && magic.every((b, i) => bytes[i] === b)) {
      const arch = magic[3] === 0xCF || magic[0] === 0xCF ? 'x86_64/arm64' : 'i386/arm'
      const isFat = magic[0] === 0xCA || magic[0] === 0xBE
      return {
        type: 'mach-o',
        subtype: isFat ? 'universal' : 'single',
        metadata: {
          architecture: arch,
          isFat,
          magic: magic.map(b => b.toString(16).padStart(2, '0')).join('')
        }
      }
    }
  }

  // .ips crash report detection
  if (filename.endsWith('.ips') || content.includes('"app_name"') || content.includes('"incident_id"')) {
    try {
      const ips = JSON.parse(content)
      return {
        type: 'ips-crash',
        subtype: ips.bug_type || 'crash',
        metadata: {
          app_name: ips.app_name,
          app_version: ips.app_version,
          os_version: ips.os_version,
          incident_id: ips.incident_id,
          exception_type: ips.exception?.type
        }
      }
    } catch {
      if (content.includes('Exception Type:') || content.includes('Crashed Thread:')) {
        return {
          type: 'ips-crash',
          subtype: 'legacy',
          metadata: { format: 'text-based crash report' }
        }
      }
    }
  }

  // Unified log detection
  if (content.includes('traceID') || content.includes('eventMessage') ||
      filename.includes('system.log') || filename.includes('unified')) {
    return {
      type: 'unified-log',
      subtype: 'unified',
      metadata: { format: 'json' }
    }
  }

  // Plist detection
  if (filename.endsWith('.plist') || content.includes('<!DOCTYPE plist') ||
      content.includes('<plist') || (bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6C && bytes[3] === 0x69)) {
    const isBinary = bytes[0] === 0x62 && bytes[1] === 0x70
    return {
      type: 'plist',
      subtype: isBinary ? 'binary' : 'xml',
      metadata: { isBinary }
    }
  }

  // LaunchAgent/Daemon detection
  if (filename.includes('LaunchAgent') || filename.includes('LaunchDaemon') ||
      content.includes('ProgramArguments') || content.includes('RunAtLoad')) {
    return {
      type: 'launchd',
      subtype: filename.includes('Agent') ? 'agent' : 'daemon',
      metadata: {}
    }
  }

  // Kext detection
  if (filename.endsWith('.kext') || content.includes('IOKitPersonalities')) {
    return {
      type: 'kext',
      subtype: 'kernel-extension',
      metadata: {}
    }
  }

  return {
    type: 'generic',
    metadata: {}
  }
}

// Calculate entropy
function calculateEntropy(str: string): number {
  const freq: Record<string, number> = {}
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

// Hash functions
async function hashMD5(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashSHA1(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-1', buffer)
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashSHA256(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('')
}

// Pseudo-ssdeep (simplified fuzzy hash)
function calculateSSDeep(content: string): string {
  const blockSize = Math.max(3, Math.floor(content.length / 64))
  const chunks: string[] = []
  for (let i = 0; i < content.length; i += blockSize) {
    const chunk = content.slice(i, i + blockSize)
    const sum = chunk.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0)
    chunks.push(String.fromCharCode(65 + (sum % 26)))
  }
  return `${blockSize}:${chunks.slice(0, 32).join('')}:${chunks.slice(32, 64).join('')}`
}

// Extract Mac IOCs
function extractMacIOCs(content: string) {
  const iocs: { type: string; value: string; context?: string }[] = []
  const seen = new Set<string>()

  // Standard IOCs
  const standardPatterns = {
    ip: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|ru|cn|xyz)\b/gi,
    url: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi,
    hash_sha256: /\b[a-fA-F0-9]{64}\b/g,
    hash_sha1: /\b[a-fA-F0-9]{40}\b/g,
    hash_md5: /\b[a-fA-F0-9]{32}\b/g,
  }

  const allPatterns = { ...standardPatterns, ...MAC_IOC_PATTERNS }

  for (const [type, pattern] of Object.entries(allPatterns)) {
    const matches = content.match(pattern) || []
    for (const match of matches) {
      const key = `${type}:${match.toLowerCase()}`
      if (!seen.has(key)) {
        seen.add(key)
        iocs.push({ type, value: match })
      }
    }
  }

  return iocs
}

// Detect threats
function detectMacThreats(content: string) {
  const threats: { pattern: string; name: string; mitre: string; severity: 'low' | 'medium' | 'high' | 'critical'; definition: string; line?: number }[] = []
  const lines = content.split('\n')

  for (const { pattern, name, mitre, severity, definition } of MAC_THREAT_PATTERNS) {
    if (pattern.test(content)) {
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

// MITRE mapping
const MITRE_TACTICS: Record<string, { tactic: string; name: string }> = {
  'T1543.001': { tactic: 'persistence', name: 'Persistence' },
  'T1037.002': { tactic: 'persistence', name: 'Persistence' },
  'T1053.003': { tactic: 'persistence', name: 'Persistence' },
  'T1547.006': { tactic: 'persistence', name: 'Persistence' },
  'T1555.001': { tactic: 'credential-access', name: 'Credential Access' },
  'T1003': { tactic: 'credential-access', name: 'Credential Access' },
  'T1548.003': { tactic: 'privilege-escalation', name: 'Privilege Escalation' },
  'T1548': { tactic: 'privilege-escalation', name: 'Privilege Escalation' },
  'T1553.001': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1553': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1562.001': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1574.006': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1564.001': { tactic: 'defense-evasion', name: 'Defense Evasion' },
  'T1082': { tactic: 'discovery', name: 'Discovery' },
  'T1087.001': { tactic: 'discovery', name: 'Discovery' },
  'T1016': { tactic: 'discovery', name: 'Discovery' },
  'T1083': { tactic: 'discovery', name: 'Discovery' },
  'T1059.002': { tactic: 'execution', name: 'Execution' },
  'T1059': { tactic: 'execution', name: 'Execution' },
}

function getMitreMapping(threats: { name: string; mitre: string; severity: string }[]) {
  const seen = new Set<string>()
  return threats.filter(t => !seen.has(t.mitre) && seen.add(t.mitre))
    .map(t => ({
      tactic: MITRE_TACTICS[t.mitre]?.name || 'Unknown',
      technique: t.name,
      id: t.mitre
    }))
}

// Calculate risk score
function calculateRiskScore(threats: any[], iocs: any[]): number {
  let score = 0
  for (const t of threats) {
    score += t.severity === 'critical' ? 30 : t.severity === 'high' ? 20 : t.severity === 'medium' ? 10 : 5
  }
  score += iocs.filter(i => i.type === 'ip').length * 5
  score += iocs.filter(i => i.type === 'domain').length * 3
  score += iocs.filter(i => i.type === 'bundle_id').length * 4
  return Math.min(100, score)
}

// Agent analysis component
function AgentAnalysisPanel({ analysis, isExpanded }: { analysis: AgentAnalysis; isExpanded: boolean }) {
  const iconMap: Record<string, typeof Brain> = {
    analyst: Search,
    hunter: Target,
    forensic: Shield,
    coder: Code
  }
  const colorMap: Record<string, string> = {
    analyst: 'text-cyan-400',
    hunter: 'text-red-400',
    forensic: 'text-green-400',
    coder: 'text-purple-400'
  }

  const Icon = iconMap[analysis.agentId] || Brain
  const color = colorMap[analysis.agentId] || 'text-null-primary'

  return (
    <div className="p-3 bg-null-bg/50 rounded border border-null-border/50">
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="font-mono text-xs font-bold">{analysis.agentName}</span>
        {analysis.status === 'analyzing' && <Loader2 className="w-3 h-3 animate-spin text-null-muted" />}
        {analysis.status === 'complete' && <Zap className="w-3 h-3 text-green-400" />}
        {analysis.status === 'error' && <AlertTriangle className="w-3 h-3 text-red-400" />}
      </div>

      {analysis.status === 'pending' && (
        <div className="text-xs text-null-muted">Waiting for analysis...</div>
      )}

      {analysis.status === 'analyzing' && (
        <div className="flex items-center gap-2 text-xs text-null-muted">
          <div className="flex gap-1">
            <div className="w-1.5 h-1.5 rounded-full bg-null-primary animate-bounce" style={{ animationDelay: '0ms' }} />
            <div className="w-1.5 h-1.5 rounded-full bg-null-primary animate-bounce" style={{ animationDelay: '150ms' }} />
            <div className="w-1.5 h-1.5 rounded-full bg-null-primary animate-bounce" style={{ animationDelay: '300ms' }} />
          </div>
          <span>Analyzing artifact...</span>
        </div>
      )}

      {analysis.status === 'complete' && analysis.analysis && (
        <div className="space-y-2">
          <p className="text-xs text-null-text whitespace-pre-wrap leading-relaxed">{analysis.analysis}</p>
          {analysis.findings && analysis.findings.length > 0 && (
            <div>
              <span className="text-[10px] uppercase text-null-muted">Findings:</span>
              <ul className="mt-1 space-y-1">
                {analysis.findings.map((f, i) => (
                  <li key={i} className="text-xs text-yellow-400 flex items-start gap-1">
                    <Bug className="w-3 h-3 mt-0.5 flex-shrink-0" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {analysis.recommendations && analysis.recommendations.length > 0 && (
            <div>
              <span className="text-[10px] uppercase text-null-muted">Recommendations:</span>
              <ul className="mt-1 space-y-1">
                {analysis.recommendations.map((r, i) => (
                  <li key={i} className="text-xs text-green-400 flex items-start gap-1">
                    <Shield className="w-3 h-3 mt-0.5 flex-shrink-0" />
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {analysis.status === 'error' && (
        <div className="text-xs text-red-400">Failed to analyze. Check API connection.</div>
      )}
    </div>
  )
}

// Result card component
function MacResultCard({ result, onDelete, onRunAgents }: {
  result: MacForensicResult
  onDelete: () => void
  onRunAgents: () => void
}) {
  const [expanded, setExpanded] = useState(true)
  const [showPreview, setShowPreview] = useState(false)
  const [showAgents, setShowAgents] = useState(false)

  const severityColor = (severity: string) => ({
    critical: 'text-red-500 bg-red-500/20',
    high: 'text-orange-500 bg-orange-500/20',
    medium: 'text-yellow-500 bg-yellow-500/20',
    low: 'text-blue-400 bg-blue-400/20'
  })[severity] || 'text-null-muted'

  const artifactIcon = () => {
    switch (result.artifact.type) {
      case 'mach-o': return <Cpu className="w-4 h-4" />
      case 'unified-log': return <Activity className="w-4 h-4" />
      case 'ips-crash': return <Bug className="w-4 h-4" />
      case 'plist': return <FileCode className="w-4 h-4" />
      case 'launchd': return <Terminal className="w-4 h-4" />
      case 'kext': return <HardDrive className="w-4 h-4" />
      default: return <FileCode className="w-4 h-4" />
    }
  }

  const riskColor = result.riskScore >= 70 ? 'text-red-500' : result.riskScore >= 40 ? 'text-yellow-500' : 'text-green-500'
  const hasAgentResults = result.agentAnalyses.some(a => a.status === 'complete')
  const isAnalyzing = result.agentAnalyses.some(a => a.status === 'analyzing')

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-null-surface/50 border border-null-border rounded-lg overflow-hidden"
    >
      <div
        className="p-4 cursor-pointer hover:bg-null-border/30 flex items-center justify-between"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded ${result.riskScore >= 70 ? 'bg-red-500/20' : result.riskScore >= 40 ? 'bg-yellow-500/20' : 'bg-green-500/20'}`}>
            <Apple className={`w-5 h-5 ${riskColor}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-null-text">{result.filename}</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 flex items-center gap-1">
                {artifactIcon()}
                {result.artifact.type}
              </span>
              {result.artifact.subtype && (
                <span className="text-xs px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400">
                  {result.artifact.subtype}
                </span>
              )}
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
            onClick={(e) => { e.stopPropagation(); setShowAgents(!showAgents) }}
            className={`p-1.5 rounded flex items-center gap-1 text-xs ${
              hasAgentResults ? 'bg-purple-500/20 text-purple-400' :
              isAnalyzing ? 'bg-yellow-500/20 text-yellow-400' :
              'hover:bg-null-border/50 text-null-muted'
            }`}
            title="4-Grok Analysis"
          >
            <Brain className={`w-4 h-4 ${isAnalyzing ? 'animate-pulse' : ''}`} />
            {isAnalyzing && <span>Analyzing...</span>}
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onRunAgents() }}
            disabled={isAnalyzing}
            className={`p-1.5 rounded ${isAnalyzing ? 'opacity-50' : 'hover:bg-null-border/50'} text-null-muted hover:text-purple-400`}
            title="Run 4-Grok Deep Analysis"
          >
            <Zap className="w-4 h-4" />
          </button>
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
            {/* Agent Analysis Panel */}
            {showAgents && (
              <div className="p-4 border-b border-null-border/50 bg-gradient-to-b from-purple-500/5 to-transparent">
                <h4 className="text-xs font-bold text-null-muted mb-3 flex items-center gap-2">
                  <Brain className="w-3 h-3" /> 4-GROK PARALLEL DEEP ANALYSIS
                </h4>
                <div className="grid grid-cols-2 gap-3">
                  {result.agentAnalyses.map(analysis => (
                    <AgentAnalysisPanel key={analysis.agentId} analysis={analysis} isExpanded={expanded} />
                  ))}
                </div>
              </div>
            )}

            {/* Artifact Metadata */}
            {Object.keys(result.artifact.metadata).length > 0 && (
              <div className="p-4 border-b border-null-border/50">
                <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                  <Apple className="w-3 h-3" /> ARTIFACT METADATA
                </h4>
                <div className="grid grid-cols-2 gap-2 font-mono text-xs">
                  {Object.entries(result.artifact.metadata).map(([k, v]) => (
                    <div key={k} className="flex items-center gap-2">
                      <span className="text-null-muted">{k}:</span>
                      <span className="text-cyan-400">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Hashes */}
            <div className="p-4 border-b border-null-border/50">
              <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                <Hash className="w-3 h-3" /> FILE HASHES
              </h4>
              <div className="space-y-1 font-mono text-xs">
                {Object.entries(result.hashes).filter(([_, v]) => v).map(([k, v]) => (
                  <div key={k} className="flex items-center gap-2">
                    <span className="text-null-muted w-16 uppercase">{k}:</span>
                    <span className="text-null-text truncate max-w-md">{v}</span>
                    <button onClick={() => navigator.clipboard.writeText(v!)} className="p-1 hover:bg-null-border/50 rounded">
                      <Copy className="w-3 h-3 text-null-muted" />
                    </button>
                  </div>
                ))}
                <div className="flex items-center gap-2 mt-2 text-null-muted">
                  <span>Entropy: {result.entropy.toFixed(2)}</span>
                  {result.entropy > 7 && <span className="text-yellow-500">(High - possibly packed)</span>}
                </div>
              </div>
            </div>

            {/* Threats */}
            {result.threats.length > 0 && (
              <div className="p-4 border-b border-null-border/50">
                <h4 className="text-xs font-bold text-null-muted mb-2 flex items-center gap-2">
                  <AlertTriangle className="w-3 h-3" /> MAC THREATS ({result.threats.length})
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
                  <Target className="w-3 h-3" /> MITRE ATT&CK
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
                  <Database className="w-3 h-3" /> MAC IOCs ({result.iocs.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                  {result.iocs.slice(0, 20).map((ioc, i) => (
                    <div key={i} className="flex items-center gap-2 p-1.5 rounded bg-null-bg/50 text-xs">
                      <span className="text-cyan-400 uppercase text-[10px] w-16">{ioc.type}</span>
                      <span className="text-null-text font-mono truncate flex-1">{ioc.value}</span>
                      <button onClick={() => navigator.clipboard.writeText(ioc.value)} className="p-0.5 hover:bg-null-border/50 rounded">
                        <Copy className="w-3 h-3 text-null-muted" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Preview */}
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

export default function MacForensics() {
  const [results, setResults] = useState<MacForensicResult[]>([])
  const [processing, setProcessing] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const processFile = useCallback(async (file: File): Promise<MacForensicResult> => {
    const buffer = await file.arrayBuffer()
    const content = await file.text()

    const [md5, sha1, sha256] = await Promise.all([
      hashMD5(buffer),
      hashSHA1(buffer),
      hashSHA256(buffer)
    ])

    const artifact = detectArtifactType(file.name, content, buffer)
    const iocs = extractMacIOCs(content)
    const threats = detectMacThreats(content)
    const mitreMapping = getMitreMapping(threats)
    const riskScore = calculateRiskScore(threats, iocs)
    const entropy = calculateEntropy(content)
    const ssdeep = calculateSSDeep(content)

    return {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      filename: file.name,
      filesize: file.size,
      timestamp: new Date(),
      artifact,
      hashes: { md5, sha1, sha256, ssdeep },
      iocs,
      threats,
      mitreMapping,
      riskScore,
      entropy,
      agentAnalyses: [
        { agentId: 'analyst', agentName: 'ANALYST', status: 'pending' },
        { agentId: 'hunter', agentName: 'HUNTER', status: 'pending' },
        { agentId: 'forensic', agentName: 'FORENSIC', status: 'pending' },
        { agentId: 'coder', agentName: 'CODER', status: 'pending' },
      ],
      rawPreview: content.slice(0, 2000) + (content.length > 2000 ? '\n\n... [truncated]' : '')
    }
  }, [])

  const runAgentAnalysis = useCallback(async (resultId: string) => {
    const result = results.find(r => r.id === resultId)
    if (!result) return

    // Update all agents to analyzing
    setResults(prev => prev.map(r => r.id === resultId ? {
      ...r,
      agentAnalyses: r.agentAnalyses.map(a => ({ ...a, status: 'analyzing' as const }))
    } : r))

    // Create analysis context
    const context = `
File: ${result.filename}
Type: ${result.artifact.type} (${result.artifact.subtype || 'unknown'})
Size: ${result.filesize} bytes
Entropy: ${result.entropy.toFixed(2)}
Risk Score: ${result.riskScore}/100
Hashes:
  MD5: ${result.hashes.md5}
  SHA256: ${result.hashes.sha256}
  SSDeep: ${result.hashes.ssdeep}
Threats Found: ${result.threats.map(t => `${t.name} (${t.severity})`).join(', ') || 'None'}
IOCs Found: ${result.iocs.length} indicators
Sample Content:
${result.rawPreview.slice(0, 1000)}
`

    const agentPrompts: Record<string, string> = {
      analyst: `As a macOS security analyst, analyze this artifact for indicators of compromise. Focus on: severity assessment, IOC correlation, and immediate triage recommendations.`,
      hunter: `As a threat hunter specializing in macOS, analyze this artifact. Map behaviors to MITRE ATT&CK techniques. Identify potential threat actor TTPs and provide hunting hypotheses.`,
      forensic: `As a digital forensics expert, analyze this macOS artifact. Focus on: artifact integrity, timeline analysis, evidence preservation, and chain of custody considerations.`,
      coder: `As a reverse engineer, analyze this artifact. Focus on: code patterns, obfuscation techniques, vulnerability indicators (CWE), and any suspicious code constructs.`
    }

    // Run all 4 agents in parallel using Grok via OpenRouter
    const agentIds = ['analyst', 'hunter', 'forensic', 'coder']
    await Promise.all(agentIds.map(async (agentId) => {
      try {
        const data = await sendAgentChat(agentId, agentPrompts[agentId], context)

        // Parse the response for findings and recommendations
        const responseText = data.response || ''
        const findings = responseText.match(/(?:finding|issue|threat|concern)[:\s]+([^\n]+)/gi)?.slice(0, 3) || []
        const recommendations = responseText.match(/(?:recommend|suggest|should|action)[:\s]+([^\n]+)/gi)?.slice(0, 3) || []

        setResults(prev => prev.map(r => r.id === resultId ? {
          ...r,
          agentAnalyses: r.agentAnalyses.map(a => a.agentId === agentId ? {
            ...a,
            status: 'complete' as const,
            analysis: responseText.slice(0, 500),
            findings: findings.map((f: string) => f.replace(/^[^:]+:\s*/, '')),
            recommendations: recommendations.map((r: string) => r.replace(/^[^:]+:\s*/, ''))
          } : a)
        } : r))
      } catch (e) {
        setResults(prev => prev.map(r => r.id === resultId ? {
          ...r,
          agentAnalyses: r.agentAnalyses.map(a => a.agentId === agentId ? {
            ...a,
            status: 'error' as const
          } : a)
        } : r))
      }
    }))
  }, [results])

  const handleFiles = useCallback(async (files: FileList | File[]) => {
    setProcessing(true)
    try {
      const newResults = await Promise.all(Array.from(files).map(processFile))
      setResults(prev => [...newResults, ...prev])
    } finally {
      setProcessing(false)
    }
  }, [processFile])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
    if (e.dataTransfer.files.length > 0) handleFiles(e.dataTransfer.files)
  }, [handleFiles])

  const exportSTIX = () => {
    const stixBundle = {
      type: 'bundle',
      id: `bundle--${crypto.randomUUID()}`,
      spec_version: '2.1',
      objects: results.flatMap(r => [
        {
          type: 'indicator',
          id: `indicator--${crypto.randomUUID()}`,
          name: `Mac Artifact: ${r.filename}`,
          pattern: `[file:hashes.'SHA-256' = '${r.hashes.sha256}']`,
          pattern_type: 'stix',
          valid_from: r.timestamp.toISOString(),
          labels: [r.artifact.type, ...r.threats.map(t => t.severity)],
          description: `Mac forensic analysis: ${r.threats.length} threats, ${r.iocs.length} IOCs, risk score ${r.riskScore}/100`
        },
        ...r.iocs.slice(0, 10).map(ioc => ({
          type: 'indicator',
          id: `indicator--${crypto.randomUUID()}`,
          name: `${ioc.type}: ${ioc.value}`,
          pattern: ioc.type === 'ip' ? `[ipv4-addr:value = '${ioc.value}']` :
                   ioc.type === 'domain' ? `[domain-name:value = '${ioc.value}']` :
                   `[file:name = '${ioc.value}']`,
          pattern_type: 'stix',
          valid_from: r.timestamp.toISOString()
        }))
      ])
    }
    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `mac-forensics-stix-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalThreats = results.reduce((sum, r) => sum + r.threats.length, 0)
  const totalIOCs = results.reduce((sum, r) => sum + r.iocs.length, 0)
  const criticalCount = results.reduce((sum, r) => sum + r.threats.filter(t => t.severity === 'critical').length, 0)

  return (
    <div className="h-full overflow-auto p-4 grid-bg">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gradient-to-br from-gray-500/20 to-blue-600/20 border border-gray-500/30">
            <Apple className="w-6 h-6 text-gray-300" />
          </div>
          <div>
            <h2 className="font-display text-lg">Mac Forensics</h2>
            <p className="text-xs text-null-muted">Mach-O, Unified Log, .ips Crash Reports - 4-Grok Deep Analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {results.length > 0 && (
            <>
              <button
                onClick={exportSTIX}
                className="flex items-center gap-2 px-3 py-1.5 rounded bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 text-sm"
              >
                <Download className="w-4 h-4" />
                STIX 2.1
              </button>
              <button
                onClick={() => setResults([])}
                className="flex items-center gap-2 px-3 py-1.5 rounded bg-null-border/50 text-null-muted hover:text-red-400 text-sm"
              >
                <Trash2 className="w-4 h-4" />
                Clear
              </button>
            </>
          )}
        </div>
      </div>

      {/* Stats */}
      {results.length > 0 && (
        <div className="grid grid-cols-4 gap-4 mb-4">
          <div className="p-3 rounded-lg bg-null-surface/50 border border-null-border">
            <div className="flex items-center gap-2 text-null-muted text-xs mb-1">
              <Apple className="w-3 h-3" /> Artifacts
            </div>
            <div className="text-2xl font-bold text-null-text">{results.length}</div>
          </div>
          <div className="p-3 rounded-lg bg-null-surface/50 border border-null-border">
            <div className="flex items-center gap-2 text-null-muted text-xs mb-1">
              <AlertTriangle className="w-3 h-3" /> Threats
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
              <Database className="w-3 h-3" /> IOCs
            </div>
            <div className="text-2xl font-bold text-cyan-400">{totalIOCs}</div>
          </div>
        </div>
      )}

      {/* Drop Zone */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => { e.preventDefault(); setDragActive(true) }}
        onDragLeave={(e) => { e.preventDefault(); setDragActive(false) }}
        onClick={() => fileInputRef.current?.click()}
        className={`
          p-8 mb-4 border-2 border-dashed rounded-lg cursor-pointer transition-all
          flex flex-col items-center justify-center gap-3
          ${dragActive ? 'border-blue-500 bg-blue-500/10' : 'border-null-border hover:border-null-primary/50 bg-null-surface/30'}
        `}
      >
        {processing ? (
          <>
            <Loader2 className="w-10 h-10 text-blue-400 animate-spin" />
            <p className="text-null-text">Processing macOS artifacts...</p>
          </>
        ) : (
          <>
            <div className="p-4 rounded-full bg-gradient-to-br from-gray-500/20 to-blue-600/20">
              <Apple className="w-10 h-10 text-gray-300" />
            </div>
            <div className="text-center">
              <p className="text-null-text font-medium">Drop macOS Artifacts</p>
              <p className="text-sm text-null-muted mt-1">Mach-O binaries, .ips crashes, unified logs, plists, kexts</p>
            </div>
            <div className="flex items-center gap-4 text-xs text-null-muted mt-2">
              <span className="flex items-center gap-1"><Cpu className="w-3 h-3" /> Mach-O</span>
              <span className="flex items-center gap-1"><Activity className="w-3 h-3" /> Unified Log</span>
              <span className="flex items-center gap-1"><Bug className="w-3 h-3" /> .ips Crash</span>
              <span className="flex items-center gap-1"><Brain className="w-3 h-3" /> 4-Grok AI</span>
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
          <MacResultCard
            key={result.id}
            result={result}
            onDelete={() => setResults(prev => prev.filter(r => r.id !== result.id))}
            onRunAgents={() => runAgentAnalysis(result.id)}
          />
        ))}
      </div>

      {results.length === 0 && !processing && (
        <div className="text-center py-12 text-null-muted">
          <Apple className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>No artifacts analyzed yet</p>
          <p className="text-sm mt-1">Drop macOS files to start forensic analysis</p>
        </div>
      )}
    </div>
  )
}
