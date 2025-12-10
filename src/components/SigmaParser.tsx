import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileSearch, Upload, Plus, Trash2, Copy, Download, AlertTriangle,
  CheckCircle, XCircle, Loader2, Play, Code, Eye, EyeOff, Target,
  Database, Filter, Zap
} from 'lucide-react'

interface SigmaRule {
  id: string
  title: string
  status?: string
  level?: string
  description?: string
  author?: string
  date?: string
  references?: string[]
  tags?: string[]
  logsource: {
    category?: string
    product?: string
    service?: string
  }
  detection: {
    selection?: Record<string, unknown>
    filter?: Record<string, unknown>
    condition: string
  }
  falsepositives?: string[]
  raw: string
}

interface LogEntry {
  id: string
  raw: string
  parsed: Record<string, string>
  timestamp?: string
}

interface MatchResult {
  rule: SigmaRule
  matched: boolean
  log_id: string
  log_preview: string
  matched_fields: string[]
}

// Built-in Sigma rules
const BUILT_IN_SIGMA_RULES: Omit<SigmaRule, 'id'>[] = [
  {
    title: 'Suspicious PowerShell Download',
    status: 'experimental',
    level: 'high',
    description: 'Detects PowerShell downloads using various methods',
    author: 'NULL SPAWN',
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*DownloadString*', '*DownloadFile*', '*Invoke-WebRequest*', '*wget*', '*curl*', '*iwr*']
      },
      condition: 'selection'
    },
    tags: ['attack.execution', 'attack.t1059.001'],
    raw: `title: Suspicious PowerShell Download
status: experimental
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
    condition: selection`
  },
  {
    title: 'Encoded PowerShell Command',
    status: 'stable',
    level: 'high',
    description: 'Detects encoded PowerShell commands',
    author: 'NULL SPAWN',
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*-enc*', '*-EncodedCommand*', '*FromBase64String*']
      },
      condition: 'selection'
    },
    tags: ['attack.defense_evasion', 'attack.t1027'],
    raw: `title: Encoded PowerShell Command
status: stable
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection`
  },
  {
    title: 'Mimikatz Usage Detection',
    status: 'stable',
    level: 'critical',
    description: 'Detects potential Mimikatz usage',
    author: 'NULL SPAWN',
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*sekurlsa*', '*lsadump*', '*mimikatz*', '*kerberos::*', '*privilege::debug*']
      },
      condition: 'selection'
    },
    tags: ['attack.credential_access', 'attack.t1003'],
    raw: `title: Mimikatz Usage Detection
status: stable
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa'
            - 'lsadump'
            - 'mimikatz'
    condition: selection`
  },
  {
    title: 'Scheduled Task Creation',
    status: 'experimental',
    level: 'medium',
    description: 'Detects scheduled task creation for persistence',
    author: 'NULL SPAWN',
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*schtasks*/create*', '*New-ScheduledTask*']
      },
      condition: 'selection'
    },
    tags: ['attack.persistence', 'attack.t1053.005'],
    raw: `title: Scheduled Task Creation
status: experimental
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'schtasks /create'
            - 'New-ScheduledTask'
    condition: selection`
  },
  {
    title: 'Registry Run Key Modification',
    status: 'stable',
    level: 'medium',
    description: 'Detects modification of registry run keys',
    author: 'NULL SPAWN',
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*\\CurrentVersion\\Run*', '*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*']
      },
      condition: 'selection'
    },
    tags: ['attack.persistence', 'attack.t1547.001'],
    raw: `title: Registry Run Key Modification
status: stable
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '\\CurrentVersion\\Run'
    condition: selection`
  },
  {
    title: 'Remote Service Creation',
    status: 'experimental',
    level: 'high',
    description: 'Detects remote service creation via sc.exe',
    author: 'NULL SPAWN',
    logsource: { category: 'process_creation', product: 'windows' },
    detection: {
      selection: {
        CommandLine: ['*sc*\\\\*create*', '*psexec*', '*wmic*/node:*process*call*create*']
      },
      condition: 'selection'
    },
    tags: ['attack.lateral_movement', 'attack.t1021.002'],
    raw: `title: Remote Service Creation
status: experimental
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sc \\\\'
            - 'psexec'
            - 'wmic /node:'
    condition: selection`
  },
  {
    title: 'Suspicious Network Connection',
    status: 'experimental',
    level: 'medium',
    description: 'Detects suspicious outbound connections',
    author: 'NULL SPAWN',
    logsource: { category: 'network_connection', product: 'windows' },
    detection: {
      selection: {
        DestinationPort: ['4444', '5555', '6666', '8888', '9999']
      },
      condition: 'selection'
    },
    tags: ['attack.command_and_control', 'attack.t1571'],
    raw: `title: Suspicious Network Connection
status: experimental
level: medium
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort:
            - 4444
            - 5555
            - 6666
    condition: selection`
  },
  {
    title: 'macOS Persistence via LaunchAgent',
    status: 'experimental',
    level: 'medium',
    description: 'Detects LaunchAgent creation on macOS',
    author: 'NULL SPAWN',
    logsource: { category: 'file_event', product: 'macos' },
    detection: {
      selection: {
        TargetFilename: ['*/LaunchAgents/*', '*/LaunchDaemons/*']
      },
      condition: 'selection'
    },
    tags: ['attack.persistence', 'attack.t1543.001'],
    raw: `title: macOS Persistence via LaunchAgent
status: experimental
level: medium
logsource:
    category: file_event
    product: macos
detection:
    selection:
        TargetFilename|contains:
            - '/LaunchAgents/'
            - '/LaunchDaemons/'
    condition: selection`
  }
]

// Parse YAML-like Sigma rule (simplified)
function parseSigmaRule(content: string): Omit<SigmaRule, 'id'> | null {
  try {
    const lines = content.split('\n')
    const rule: Record<string, unknown> = {}
    let currentKey = ''
    let inDetection = false
    let inLogsource = false
    let detectionContent: Record<string, unknown> = {}
    let logsourceContent: Record<string, unknown> = {}
    let currentSelection: string[] = []
    let currentSelectionKey = ''

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue

      // Top-level keys
      const keyMatch = line.match(/^(\w+):(.*)/)
      if (keyMatch && !line.startsWith(' ') && !line.startsWith('\t')) {
        currentKey = keyMatch[1]
        const value = keyMatch[2].trim()

        if (currentKey === 'detection') {
          inDetection = true
          inLogsource = false
        } else if (currentKey === 'logsource') {
          inLogsource = true
          inDetection = false
        } else {
          inDetection = false
          inLogsource = false
          if (value) {
            rule[currentKey] = value
          }
        }
        continue
      }

      // Nested content
      if (inDetection) {
        const nestedMatch = trimmed.match(/^(\w+):(.*)/)
        if (nestedMatch) {
          if (currentSelectionKey && currentSelection.length > 0) {
            detectionContent[currentSelectionKey] = { CommandLine: currentSelection }
            currentSelection = []
          }
          currentSelectionKey = nestedMatch[1]
          const val = nestedMatch[2].trim()
          if (val) detectionContent[currentSelectionKey] = val
        } else if (trimmed.startsWith('- ')) {
          currentSelection.push(trimmed.slice(2).replace(/['"]/g, ''))
        }
      } else if (inLogsource) {
        const nestedMatch = trimmed.match(/^(\w+):(.*)/)
        if (nestedMatch) {
          logsourceContent[nestedMatch[1]] = nestedMatch[2].trim()
        }
      }
    }

    // Finalize
    if (currentSelectionKey && currentSelection.length > 0) {
      detectionContent[currentSelectionKey] = { CommandLine: currentSelection }
    }

    return {
      title: String(rule.title || 'Untitled Rule'),
      status: String(rule.status || 'experimental'),
      level: String(rule.level || 'medium'),
      description: String(rule.description || ''),
      author: String(rule.author || ''),
      logsource: logsourceContent as SigmaRule['logsource'],
      detection: {
        ...detectionContent,
        condition: String(detectionContent.condition || 'selection')
      } as SigmaRule['detection'],
      tags: [],
      raw: content
    }
  } catch {
    return null
  }
}

// Match Sigma rule against log entry
function matchSigmaRule(rule: SigmaRule, log: LogEntry): boolean {
  const detection = rule.detection
  const selection = detection.selection

  if (!selection) return false

  // Check if any selection criteria matches
  for (const [field, patterns] of Object.entries(selection)) {
    const logValue = log.parsed[field] || log.raw

    if (Array.isArray(patterns)) {
      for (const pattern of patterns) {
        const searchPattern = String(pattern).replace(/\*/g, '.*')
        const regex = new RegExp(searchPattern, 'i')
        if (regex.test(logValue)) {
          return true
        }
      }
    } else if (typeof patterns === 'object' && patterns !== null) {
      // Nested field (e.g., CommandLine)
      for (const [, innerPatterns] of Object.entries(patterns)) {
        if (Array.isArray(innerPatterns)) {
          for (const pattern of innerPatterns) {
            const searchPattern = String(pattern).replace(/\*/g, '.*')
            const regex = new RegExp(searchPattern, 'i')
            if (regex.test(logValue)) {
              return true
            }
          }
        }
      }
    }
  }

  return false
}

// Parse log entry
function parseLogEntry(raw: string): LogEntry {
  const parsed: Record<string, string> = {}

  // Extract key-value pairs
  const kvMatches = raw.matchAll(/(\w+)[=:]"?([^"\s,]+)"?/g)
  for (const match of kvMatches) {
    parsed[match[1]] = match[2]
  }

  // Common field extraction
  const cmdMatch = raw.match(/CommandLine[=:]\s*["']?(.+?)["']?(?:\s|$)/i)
  if (cmdMatch) parsed.CommandLine = cmdMatch[1]

  const imageMatch = raw.match(/Image[=:]\s*["']?(.+?)["']?(?:\s|$)/i)
  if (imageMatch) parsed.Image = imageMatch[1]

  const userMatch = raw.match(/User[=:]\s*["']?(.+?)["']?(?:\s|$)/i)
  if (userMatch) parsed.User = userMatch[1]

  return {
    id: Math.random().toString(36).substr(2, 9),
    raw,
    parsed,
    timestamp: new Date().toISOString()
  }
}

export default function SigmaParser() {
  const [rules, setRules] = useState<SigmaRule[]>(
    BUILT_IN_SIGMA_RULES.map((r, i) => ({ ...r, id: `builtin_${i}` }))
  )
  const [customRuleText, setCustomRuleText] = useState('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [results, setResults] = useState<MatchResult[]>([])
  const [scanning, setScanning] = useState(false)
  const [showRules, setShowRules] = useState(true)
  const [selectedLevel, setSelectedLevel] = useState<string>('all')
  const [logInput, setLogInput] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const levels = ['all', 'critical', 'high', 'medium', 'low']
  const filteredRules = selectedLevel === 'all'
    ? rules
    : rules.filter(r => r.level === selectedLevel)

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const processLogFile = async (file: File) => {
    const content = await file.text()
    const lines = content.split('\n').filter(l => l.trim())
    const newLogs = lines.map(parseLogEntry)
    setLogs(prev => [...prev, ...newLogs])
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processLogFile(e.dataTransfer.files[0])
    }
  }, [])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processLogFile(e.target.files[0])
    }
  }

  const addLogEntry = () => {
    if (!logInput.trim()) return
    const newLog = parseLogEntry(logInput.trim())
    setLogs(prev => [...prev, newLog])
    setLogInput('')
  }

  const addCustomRule = () => {
    if (!customRuleText.trim()) return
    const parsed = parseSigmaRule(customRuleText)
    if (parsed) {
      const newRule: SigmaRule = {
        ...parsed,
        id: `custom_${Date.now()}`
      }
      setRules(prev => [...prev, newRule])
      setCustomRuleText('')
    }
  }

  const runDetection = async () => {
    if (logs.length === 0) return

    setScanning(true)
    setResults([])

    // Small delay for UI feedback
    await new Promise(resolve => setTimeout(resolve, 100))

    const newResults: MatchResult[] = []

    for (const log of logs) {
      for (const rule of rules) {
        const matched = matchSigmaRule(rule, log)
        if (matched) {
          newResults.push({
            rule,
            matched: true,
            log_id: log.id,
            log_preview: log.raw.substring(0, 100),
            matched_fields: Object.keys(log.parsed)
          })
        }
      }
    }

    setResults(newResults)
    setScanning(false)
  }

  const deleteRule = (id: string) => {
    setRules(prev => prev.filter(r => r.id !== id))
  }

  const clearLogs = () => {
    setLogs([])
    setResults([])
  }

  const exportResults = () => {
    const report = {
      scan_time: new Date().toISOString(),
      total_logs: logs.length,
      total_rules: rules.length,
      total_matches: results.length,
      matches: results.map(r => ({
        rule: r.rule.title,
        level: r.rule.level,
        mitre: r.rule.tags,
        log_preview: r.log_preview
      }))
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sigma-scan-${Date.now()}.json`
    a.click()
  }

  const getLevelColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/20 border-red-500/30'
      case 'high': return 'text-orange-500 bg-orange-500/20 border-orange-500/30'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20 border-yellow-500/30'
      case 'low': return 'text-blue-500 bg-blue-500/20 border-blue-500/30'
      default: return 'text-null-muted bg-null-border/50 border-null-border'
    }
  }

  return (
    <div className="h-full overflow-auto p-4 grid-bg">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileSearch className="w-6 h-6 text-null-primary" />
          <div>
            <h2 className="font-display text-lg">Sigma Rule Engine</h2>
            <p className="text-xs text-null-muted">{rules.length} rules loaded | {logs.length} log entries</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={runDetection}
            disabled={scanning || logs.length === 0}
            className={`flex items-center gap-2 px-4 py-2 rounded border transition-all ${
              scanning || logs.length === 0
                ? 'bg-null-border/30 border-null-border text-null-muted cursor-not-allowed'
                : 'bg-null-primary/20 border-null-primary/50 text-null-primary hover:bg-null-primary/30'
            }`}
          >
            {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Run Detection
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left Panel - Log Input */}
        <div className="space-y-4">
          {/* Drop Zone */}
          <div
            className={`
              border-2 border-dashed rounded-lg p-6 text-center transition-all cursor-pointer
              ${dragActive
                ? 'border-null-primary bg-null-primary/10'
                : 'border-null-border hover:border-null-primary/50 hover:bg-null-surface/50'}
            `}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileSelect}
              className="hidden"
              accept=".log,.txt,.json,.csv"
            />
            <Upload className={`w-8 h-8 mx-auto mb-2 ${dragActive ? 'text-null-primary' : 'text-null-muted'}`} />
            <p className="text-sm text-null-text">Drop log file or click to select</p>
          </div>

          {/* Manual Log Input */}
          <div className="bg-null-surface border border-null-border rounded-lg p-3">
            <label className="text-xs text-null-muted block mb-2">Add Log Entry</label>
            <textarea
              value={logInput}
              onChange={(e) => setLogInput(e.target.value)}
              placeholder="Paste log line here..."
              className="w-full h-20 bg-null-bg border border-null-border rounded p-2 text-xs font-mono text-null-text placeholder:text-null-muted/50 outline-none focus:border-null-primary/50 resize-none"
            />
            <button
              onClick={addLogEntry}
              disabled={!logInput.trim()}
              className={`mt-2 w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded text-sm transition-all ${
                logInput.trim()
                  ? 'bg-null-primary/20 border border-null-primary/50 text-null-primary'
                  : 'bg-null-border/30 border border-null-border text-null-muted cursor-not-allowed'
              }`}
            >
              <Plus className="w-4 h-4" />
              Add Entry
            </button>
          </div>

          {/* Log Entries List */}
          <div className="bg-null-surface border border-null-border rounded-lg overflow-hidden">
            <div className="p-3 border-b border-null-border flex items-center justify-between">
              <span className="text-sm font-medium">Log Entries ({logs.length})</span>
              <button
                onClick={clearLogs}
                disabled={logs.length === 0}
                className="text-xs text-null-muted hover:text-red-400"
              >
                Clear All
              </button>
            </div>
            <div className="max-h-60 overflow-y-auto">
              {logs.length === 0 ? (
                <div className="p-4 text-center text-null-muted text-sm">
                  <Database className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  No logs loaded
                </div>
              ) : (
                logs.slice(0, 50).map((log, i) => (
                  <div key={log.id} className="p-2 border-b border-null-border/50 last:border-0 hover:bg-null-bg/30">
                    <p className="text-xs font-mono text-null-text truncate">{log.raw}</p>
                    <p className="text-[10px] text-null-muted mt-1">
                      {Object.keys(log.parsed).length} fields parsed
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Middle Panel - Rules */}
        <div className="space-y-4">
          {/* Add Custom Rule */}
          <div className="bg-null-surface border border-null-border rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium flex items-center gap-2">
                <Plus className="w-4 h-4 text-null-primary" />
                Add Custom Rule
              </span>
            </div>
            <textarea
              value={customRuleText}
              onChange={(e) => setCustomRuleText(e.target.value)}
              placeholder={`title: My Detection Rule
status: experimental
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'malicious_string'
    condition: selection`}
              className="w-full h-36 bg-null-bg border border-null-border rounded p-2 text-xs font-mono text-null-text placeholder:text-null-muted/50 outline-none focus:border-null-primary/50 resize-none"
            />
            <button
              onClick={addCustomRule}
              disabled={!customRuleText.trim()}
              className={`mt-2 w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded text-sm transition-all ${
                customRuleText.trim()
                  ? 'bg-indigo-500/20 border border-indigo-500/50 text-indigo-400'
                  : 'bg-null-border/30 border border-null-border text-null-muted cursor-not-allowed'
              }`}
            >
              <Plus className="w-4 h-4" />
              Add Rule
            </button>
          </div>

          {/* Level Filter */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2">
            {levels.map(level => (
              <button
                key={level}
                onClick={() => setSelectedLevel(level)}
                className={`px-2 py-1 rounded text-xs whitespace-nowrap transition-all ${
                  selectedLevel === level
                    ? getLevelColor(level === 'all' ? undefined : level)
                    : 'bg-null-border/50 text-null-muted hover:bg-null-border'
                } border`}
              >
                {level}
              </button>
            ))}
          </div>

          {/* Rules List */}
          <div className="bg-null-surface border border-null-border rounded-lg overflow-hidden">
            <div className="p-3 border-b border-null-border flex items-center justify-between">
              <span className="text-sm font-medium">Detection Rules ({filteredRules.length})</span>
              <button
                onClick={() => setShowRules(!showRules)}
                className="p-1 hover:bg-null-border/50 rounded"
              >
                {showRules ? <EyeOff className="w-4 h-4 text-null-muted" /> : <Eye className="w-4 h-4 text-null-muted" />}
              </button>
            </div>
            <AnimatePresence>
              {showRules && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="max-h-96 overflow-y-auto"
                >
                  {filteredRules.map(rule => (
                    <div key={rule.id} className="p-3 border-b border-null-border/50 last:border-0 hover:bg-null-bg/30">
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] border ${getLevelColor(rule.level)}`}>
                              {rule.level}
                            </span>
                            <span className="text-sm font-medium text-null-text truncate">{rule.title}</span>
                          </div>
                          {rule.description && (
                            <p className="text-xs text-null-muted line-clamp-2">{rule.description}</p>
                          )}
                          {rule.tags && rule.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {rule.tags.slice(0, 3).map((tag, i) => (
                                <span key={i} className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 text-[10px]">
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        {rule.id.startsWith('custom_') && (
                          <button
                            onClick={() => deleteRule(rule.id)}
                            className="p-1 hover:bg-red-500/20 rounded text-red-400 ml-2"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Right Panel - Results */}
        <div className="space-y-4">
          {/* Results Header */}
          <div className={`rounded-lg p-4 border ${
            results.length === 0
              ? 'bg-null-surface border-null-border'
              : 'bg-red-500/10 border-red-500/30'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {results.length === 0 ? (
                  <Filter className="w-6 h-6 text-null-muted" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                )}
                <div>
                  <p className="font-medium text-null-text">
                    {results.length === 0 ? 'No Detections' : `${results.length} Detection${results.length > 1 ? 's' : ''}`}
                  </p>
                  <p className="text-xs text-null-muted">
                    {logs.length} logs scanned with {rules.length} rules
                  </p>
                </div>
              </div>
              {results.length > 0 && (
                <button
                  onClick={exportResults}
                  className="flex items-center gap-2 px-3 py-1.5 rounded bg-null-bg/50 border border-null-border text-sm text-null-muted hover:text-null-text"
                >
                  <Download className="w-4 h-4" />
                  Export
                </button>
              )}
            </div>
          </div>

          {/* Results List */}
          <div className="bg-null-surface border border-null-border rounded-lg overflow-hidden">
            <div className="max-h-[500px] overflow-y-auto">
              {results.length === 0 ? (
                <div className="p-8 text-center text-null-muted">
                  <Target className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">Run detection to see results</p>
                  <p className="text-xs mt-1">Load logs and click "Run Detection"</p>
                </div>
              ) : (
                results.map((result, idx) => (
                  <div key={idx} className="p-3 border-b border-null-border/50 last:border-0">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className={`w-5 h-5 flex-shrink-0 mt-0.5 ${
                        result.rule.level === 'critical' ? 'text-red-500' :
                        result.rule.level === 'high' ? 'text-orange-500' :
                        'text-yellow-500'
                      }`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${getLevelColor(result.rule.level)}`}>
                            {result.rule.level}
                          </span>
                          <span className="text-sm font-medium text-null-text">{result.rule.title}</span>
                        </div>
                        <p className="text-xs text-null-muted font-mono bg-null-bg/50 p-2 rounded mt-2 break-all">
                          {result.log_preview}...
                        </p>
                        {result.rule.tags && result.rule.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {result.rule.tags.map((tag, i) => (
                              <span key={i} className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 text-[10px]">
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-null-surface border border-null-border rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">
                {results.filter(r => r.rule.level === 'critical').length}
              </p>
              <p className="text-xs text-null-muted">Critical</p>
            </div>
            <div className="bg-null-surface border border-null-border rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-orange-400">
                {results.filter(r => r.rule.level === 'high').length}
              </p>
              <p className="text-xs text-null-muted">High</p>
            </div>
            <div className="bg-null-surface border border-null-border rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-yellow-400">
                {results.filter(r => r.rule.level === 'medium').length}
              </p>
              <p className="text-xs text-null-muted">Medium</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
