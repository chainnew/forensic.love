import { useState, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, Search, Upload, FileCode, AlertTriangle, CheckCircle,
  XCircle, Loader2, Plus, Trash2, Copy, Download, Zap, Code,
  Eye, EyeOff, Play, Bug
} from 'lucide-react'

interface YaraRule {
  id: string
  name: string
  content: string
  enabled: boolean
  category: string
}

interface ScanResult {
  rule_name: string
  rule_id: string
  matches: {
    offset: number
    length: number
    data: string
    identifier: string
  }[]
  meta: Record<string, string>
  strings_matched: number
}

interface ScanReport {
  filename: string
  file_size: number
  scan_time_ms: number
  rules_checked: number
  matches: ScanResult[]
  clean: boolean
  sha256?: string
}

// Built-in YARA rules for common malware patterns
const BUILT_IN_RULES: YaraRule[] = [
  {
    id: 'builtin_1',
    name: 'Suspicious_PowerShell',
    category: 'malware',
    enabled: true,
    content: `rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc" nocase
        $bypass1 = "bypass" nocase
        $bypass2 = "-ep bypass" nocase
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "Invoke-WebRequest" nocase
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX(" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $b64 = "FromBase64String" nocase
    condition:
        2 of them
}`
  },
  {
    id: 'builtin_2',
    name: 'Mimikatz_Strings',
    category: 'credential',
    enabled: true,
    content: `rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
        mitre = "T1003"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "lsadump" nocase
        $m4 = "kerberos::golden" nocase
        $m5 = "privilege::debug" nocase
        $m6 = "gentilkiwi" nocase
        $m7 = "wdigest" nocase
    condition:
        2 of them
}`
  },
  {
    id: 'builtin_3',
    name: 'Cobalt_Strike_Beacon',
    category: 'c2',
    enabled: true,
    content: `rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity = "critical"
        mitre = "T1071.001"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" nocase
        $pipe2 = "\\\\.\\pipe\\msse-" nocase
        $ua1 = "Mozilla/4.0 (compatible; MSIE 7.0" nocase
        $ua2 = "Mozilla/5.0 (compatible; MSIE 9.0" nocase
        $sleep = "sleeptime" nocase
        $beacon = "beacon" nocase
        $meta = "%s as %s\\%s: %d" nocase
    condition:
        2 of them
}`
  },
  {
    id: 'builtin_4',
    name: 'Shell_Code_Patterns',
    category: 'exploit',
    enabled: true,
    content: `rule Shell_Code_Patterns {
    meta:
        description = "Detects common shellcode patterns"
        severity = "high"
        mitre = "T1055"
    strings:
        $nop = { 90 90 90 90 90 }
        $pushad = { 60 }
        $getpc = { e8 00 00 00 00 }
        $kernel32 = "kernel32.dll" nocase
        $virtualalloc = "VirtualAlloc" nocase
        $createthread = "CreateThread" nocase
        $loadlibrary = "LoadLibrary" nocase
    condition:
        3 of them
}`
  },
  {
    id: 'builtin_5',
    name: 'Webshell_PHP',
    category: 'webshell',
    enabled: true,
    content: `rule Webshell_PHP {
    meta:
        description = "Detects PHP webshell patterns"
        severity = "critical"
        mitre = "T1505.003"
    strings:
        $eval1 = "eval($_" nocase
        $eval2 = "eval($" nocase
        $base64 = "base64_decode($_" nocase
        $exec = "exec($_" nocase
        $system = "system($_" nocase
        $shell = "shell_exec(" nocase
        $passthru = "passthru(" nocase
        $proc = "proc_open(" nocase
    condition:
        2 of them
}`
  },
  {
    id: 'builtin_6',
    name: 'Ransomware_Indicators',
    category: 'ransomware',
    enabled: true,
    content: `rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware indicators"
        severity = "critical"
        mitre = "T1486"
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ransom1 = "bitcoin" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "recover your files" nocase
        $ransom4 = "your files have been" nocase
        $shadow = "vssadmin delete shadows" nocase
        $wmic = "wmic shadowcopy delete" nocase
    condition:
        3 of them
}`
  },
  {
    id: 'builtin_7',
    name: 'Mac_Malware_Patterns',
    category: 'macos',
    enabled: true,
    content: `rule Mac_Malware_Patterns {
    meta:
        description = "Detects macOS malware patterns"
        severity = "high"
        mitre = "T1059.004"
    strings:
        $launch_agent = "LaunchAgents" nocase
        $launch_daemon = "LaunchDaemons" nocase
        $osascript = "osascript -e" nocase
        $keychain = "security find-generic-password" nocase
        $tcc = "TCC.db" nocase
        $dylib = "DYLD_INSERT_LIBRARIES" nocase
        $sip = "csrutil disable" nocase
        $xprotect = "XProtect" nocase
    condition:
        2 of them
}`
  },
  {
    id: 'builtin_8',
    name: 'Persistence_Registry',
    category: 'persistence',
    enabled: true,
    content: `rule Persistence_Registry {
    meta:
        description = "Detects registry persistence mechanisms"
        severity = "medium"
        mitre = "T1547.001"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $services = "SYSTEM\\CurrentControlSet\\Services" nocase
        $shell = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" nocase
    condition:
        any of them
}`
  }
]

// Simple YARA-like pattern matcher (client-side implementation)
function matchYaraRule(content: string, rule: YaraRule): ScanResult | null {
  // Parse the rule to extract strings and conditions
  const stringsMatch = rule.content.match(/strings:\s*([\s\S]*?)(?:condition:|$)/i)
  const conditionMatch = rule.content.match(/condition:\s*([\s\S]*?)(?:}|$)/i)
  const metaMatch = rule.content.match(/meta:\s*([\s\S]*?)(?:strings:|condition:|$)/i)

  if (!stringsMatch) return null

  const stringsSection = stringsMatch[1]
  const condition = conditionMatch?.[1]?.trim() || 'any of them'

  // Parse meta
  const meta: Record<string, string> = {}
  if (metaMatch) {
    const metaLines = metaMatch[1].split('\n')
    for (const line of metaLines) {
      const m = line.match(/(\w+)\s*=\s*"([^"]+)"/)
      if (m) meta[m[1]] = m[2]
    }
  }

  // Parse string patterns
  const patterns: { id: string; pattern: RegExp; isHex: boolean }[] = []
  const stringLines = stringsSection.split('\n')

  for (const line of stringLines) {
    const stringMatch = line.match(/(\$\w+)\s*=\s*(?:"([^"]+)"|\{([^}]+)\})\s*(nocase)?/i)
    if (stringMatch) {
      const [, id, strPattern, hexPattern, nocase] = stringMatch
      if (strPattern) {
        // String pattern
        const flags = nocase ? 'gi' : 'g'
        try {
          patterns.push({
            id,
            pattern: new RegExp(strPattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), flags),
            isHex: false
          })
        } catch {}
      } else if (hexPattern) {
        // Hex pattern - convert to regex
        const hexRegex = hexPattern
          .replace(/\s+/g, '')
          .replace(/\?\?/g, '..')
          .match(/.{2}/g)
          ?.map(b => b === '..' ? '.' : `\\x${b}`)
          .join('') || ''
        try {
          patterns.push({ id, pattern: new RegExp(hexRegex, 'g'), isHex: true })
        } catch {}
      }
    }
  }

  // Match patterns
  const matches: ScanResult['matches'] = []
  const matchedPatterns = new Set<string>()

  for (const { id, pattern } of patterns) {
    let match
    while ((match = pattern.exec(content)) !== null) {
      matchedPatterns.add(id)
      matches.push({
        offset: match.index,
        length: match[0].length,
        data: match[0].substring(0, 50),
        identifier: id
      })
    }
  }

  // Evaluate condition
  let conditionMet = false
  const numMatched = matchedPatterns.size
  const totalPatterns = patterns.length

  if (/any of them/i.test(condition)) {
    conditionMet = numMatched > 0
  } else if (/all of them/i.test(condition)) {
    conditionMet = numMatched === totalPatterns
  } else if (/(\d+) of them/i.test(condition)) {
    const required = parseInt(condition.match(/(\d+) of them/i)?.[1] || '1')
    conditionMet = numMatched >= required
  } else {
    // Default: any match
    conditionMet = numMatched > 0
  }

  if (conditionMet && matches.length > 0) {
    return {
      rule_name: rule.name,
      rule_id: rule.id,
      matches: matches.slice(0, 20), // Limit matches
      meta,
      strings_matched: numMatched
    }
  }

  return null
}

export default function YaraScanner() {
  const [rules, setRules] = useState<YaraRule[]>(BUILT_IN_RULES)
  const [customRuleText, setCustomRuleText] = useState('')
  const [scanResults, setScanResults] = useState<ScanReport | null>(null)
  const [scanning, setScanning] = useState(false)
  const [showRules, setShowRules] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState<string>('all')
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const categories = ['all', ...Array.from(new Set(rules.map(r => r.category)))]

  const filteredRules = selectedCategory === 'all'
    ? rules
    : rules.filter(r => r.category === selectedCategory)

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const processFile = async (file: File) => {
    setScanning(true)
    setScanResults(null)
    const startTime = performance.now()

    try {
      const content = await file.text()
      const enabledRules = rules.filter(r => r.enabled)
      const matches: ScanResult[] = []

      for (const rule of enabledRules) {
        const result = matchYaraRule(content, rule)
        if (result) {
          matches.push(result)
        }
      }

      // Calculate SHA256
      const encoder = new TextEncoder()
      const data = encoder.encode(content)
      const hashBuffer = await crypto.subtle.digest('SHA-256', data)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

      setScanResults({
        filename: file.name,
        file_size: file.size,
        scan_time_ms: Math.round(performance.now() - startTime),
        rules_checked: enabledRules.length,
        matches,
        clean: matches.length === 0,
        sha256
      })
    } catch (error) {
      console.error('Scan error:', error)
    } finally {
      setScanning(false)
    }
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0])
    }
  }, [rules])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0])
    }
  }

  const addCustomRule = () => {
    if (!customRuleText.trim()) return

    // Try to parse rule name
    const nameMatch = customRuleText.match(/rule\s+(\w+)/i)
    const name = nameMatch?.[1] || `Custom_Rule_${Date.now()}`

    const newRule: YaraRule = {
      id: `custom_${Date.now()}`,
      name,
      content: customRuleText,
      enabled: true,
      category: 'custom'
    }

    setRules(prev => [...prev, newRule])
    setCustomRuleText('')
  }

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r =>
      r.id === id ? { ...r, enabled: !r.enabled } : r
    ))
  }

  const deleteRule = (id: string) => {
    setRules(prev => prev.filter(r => r.id !== id))
  }

  const exportResults = () => {
    if (!scanResults) return
    const blob = new Blob([JSON.stringify(scanResults, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `yara-scan-${scanResults.filename}-${Date.now()}.json`
    a.click()
  }

  const getSeverityColor = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/20'
      case 'high': return 'text-orange-500 bg-orange-500/20'
      case 'medium': return 'text-yellow-500 bg-yellow-500/20'
      case 'low': return 'text-blue-500 bg-blue-500/20'
      default: return 'text-null-muted bg-null-border/50'
    }
  }

  return (
    <div className="h-full overflow-auto p-4 grid-bg">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-null-primary" />
          <div>
            <h2 className="font-display text-lg">YARA Scanner</h2>
            <p className="text-xs text-null-muted">Client-side pattern matching with {rules.filter(r => r.enabled).length} active rules</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowRules(!showRules)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded border transition-all ${
              showRules
                ? 'bg-null-primary/20 border-null-primary/50 text-null-primary'
                : 'bg-null-surface border-null-border text-null-muted hover:bg-null-border/50'
            }`}
          >
            {showRules ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            <span className="text-sm">{showRules ? 'Hide' : 'Show'} Rules</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left Panel - Drop Zone & Results */}
        <div className="space-y-4">
          {/* Drop Zone */}
          <div
            className={`
              border-2 border-dashed rounded-lg p-8 text-center transition-all cursor-pointer
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
            />
            {scanning ? (
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="w-12 h-12 text-null-primary animate-spin" />
                <p className="text-null-text">Scanning with {rules.filter(r => r.enabled).length} rules...</p>
              </div>
            ) : (
              <>
                <Upload className={`w-12 h-12 mx-auto mb-3 ${dragActive ? 'text-null-primary' : 'text-null-muted'}`} />
                <p className="text-null-text font-medium">Drop file to scan</p>
                <p className="text-sm text-null-muted mt-1">or click to select</p>
              </>
            )}
          </div>

          {/* Scan Results */}
          <AnimatePresence>
            {scanResults && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="bg-null-surface border border-null-border rounded-lg overflow-hidden"
              >
                {/* Result Header */}
                <div className={`p-4 flex items-center justify-between ${
                  scanResults.clean
                    ? 'bg-green-500/10 border-b border-green-500/30'
                    : 'bg-red-500/10 border-b border-red-500/30'
                }`}>
                  <div className="flex items-center gap-3">
                    {scanResults.clean ? (
                      <CheckCircle className="w-6 h-6 text-green-500" />
                    ) : (
                      <XCircle className="w-6 h-6 text-red-500" />
                    )}
                    <div>
                      <p className="font-medium text-null-text">{scanResults.filename}</p>
                      <p className="text-xs text-null-muted">
                        {(scanResults.file_size / 1024).toFixed(2)} KB | {scanResults.scan_time_ms}ms | {scanResults.rules_checked} rules checked
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-sm font-medium ${
                      scanResults.clean ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                    }`}>
                      {scanResults.clean ? 'CLEAN' : `${scanResults.matches.length} DETECTION${scanResults.matches.length > 1 ? 'S' : ''}`}
                    </span>
                    <button
                      onClick={exportResults}
                      className="p-2 hover:bg-null-border/50 rounded text-null-muted"
                      title="Export Results"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* SHA256 */}
                {scanResults.sha256 && (
                  <div className="px-4 py-2 bg-null-bg/50 border-b border-null-border flex items-center gap-2">
                    <span className="text-xs text-null-muted">SHA256:</span>
                    <code className="text-xs text-null-text font-mono">{scanResults.sha256}</code>
                    <button
                      onClick={() => navigator.clipboard.writeText(scanResults.sha256!)}
                      className="p-1 hover:bg-null-border/50 rounded"
                    >
                      <Copy className="w-3 h-3 text-null-muted" />
                    </button>
                  </div>
                )}

                {/* Matches */}
                {scanResults.matches.length > 0 && (
                  <div className="p-4 space-y-3 max-h-80 overflow-y-auto">
                    {scanResults.matches.map((match, idx) => (
                      <div key={idx} className="bg-null-bg/50 border border-null-border rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Bug className="w-4 h-4 text-red-400" />
                            <span className="font-medium text-null-text">{match.rule_name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {match.meta?.severity && (
                              <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(match.meta.severity)}`}>
                                {match.meta.severity}
                              </span>
                            )}
                            {match.meta?.mitre && (
                              <span className="px-2 py-0.5 rounded text-xs bg-purple-500/20 text-purple-400">
                                {match.meta.mitre}
                              </span>
                            )}
                          </div>
                        </div>
                        {match.meta?.description && (
                          <p className="text-xs text-null-muted mb-2">{match.meta.description}</p>
                        )}
                        <div className="text-xs">
                          <span className="text-null-muted">{match.strings_matched} pattern(s) matched, {match.matches.length} occurrence(s)</span>
                        </div>
                        {/* Show first few matches */}
                        <div className="mt-2 space-y-1">
                          {match.matches.slice(0, 3).map((m, i) => (
                            <div key={i} className="flex items-center gap-2 text-xs font-mono bg-null-surface/50 p-1.5 rounded">
                              <span className="text-null-muted">{m.identifier}</span>
                              <span className="text-cyan-400">@{m.offset}</span>
                              <span className="text-yellow-400 truncate max-w-xs">"{m.data}"</span>
                            </div>
                          ))}
                          {match.matches.length > 3 && (
                            <p className="text-xs text-null-muted">...and {match.matches.length - 3} more</p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right Panel - Rules */}
        <div className="space-y-4">
          {/* Add Custom Rule */}
          <div className="bg-null-surface border border-null-border rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Plus className="w-4 h-4 text-null-primary" />
                <span className="text-sm font-medium">Add Custom Rule</span>
              </div>
            </div>
            <textarea
              value={customRuleText}
              onChange={(e) => setCustomRuleText(e.target.value)}
              placeholder={`rule My_Custom_Rule {
    meta:
        description = "Custom detection rule"
        severity = "medium"
    strings:
        $s1 = "malicious_string"
    condition:
        any of them
}`}
              className="w-full h-32 bg-null-bg border border-null-border rounded p-3 text-sm font-mono text-null-text placeholder:text-null-muted/50 outline-none focus:border-null-primary/50 resize-none"
            />
            <button
              onClick={addCustomRule}
              disabled={!customRuleText.trim()}
              className={`mt-2 w-full flex items-center justify-center gap-2 px-4 py-2 rounded transition-all ${
                customRuleText.trim()
                  ? 'bg-null-primary/20 border border-null-primary/50 text-null-primary hover:bg-null-primary/30'
                  : 'bg-null-border/30 border border-null-border text-null-muted cursor-not-allowed'
              }`}
            >
              <Plus className="w-4 h-4" />
              Add Rule
            </button>
          </div>

          {/* Rules List */}
          <AnimatePresence>
            {showRules && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="bg-null-surface border border-null-border rounded-lg overflow-hidden"
              >
                {/* Category Filter */}
                <div className="p-3 border-b border-null-border flex items-center gap-2 overflow-x-auto">
                  {categories.map(cat => (
                    <button
                      key={cat}
                      onClick={() => setSelectedCategory(cat)}
                      className={`px-2 py-1 rounded text-xs whitespace-nowrap transition-all ${
                        selectedCategory === cat
                          ? 'bg-null-primary/20 text-null-primary'
                          : 'bg-null-border/50 text-null-muted hover:bg-null-border'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>

                {/* Rules */}
                <div className="max-h-96 overflow-y-auto">
                  {filteredRules.map(rule => (
                    <div
                      key={rule.id}
                      className="p-3 border-b border-null-border/50 last:border-0 hover:bg-null-bg/30"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => toggleRule(rule.id)}
                            className={`w-8 h-5 rounded-full transition-all ${
                              rule.enabled ? 'bg-null-primary' : 'bg-null-border'
                            }`}
                          >
                            <div className={`w-4 h-4 bg-white rounded-full transition-all ${
                              rule.enabled ? 'translate-x-3.5' : 'translate-x-0.5'
                            }`} />
                          </button>
                          <div>
                            <p className="text-sm font-medium text-null-text">{rule.name}</p>
                            <p className="text-xs text-null-muted">{rule.category}</p>
                          </div>
                        </div>
                        {rule.id.startsWith('custom_') && (
                          <button
                            onClick={() => deleteRule(rule.id)}
                            className="p-1.5 hover:bg-red-500/20 rounded text-red-400"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-null-surface border border-null-border rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-null-primary">{rules.length}</p>
              <p className="text-xs text-null-muted">Total Rules</p>
            </div>
            <div className="bg-null-surface border border-null-border rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{rules.filter(r => r.enabled).length}</p>
              <p className="text-xs text-null-muted">Active</p>
            </div>
            <div className="bg-null-surface border border-null-border rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-cyan-400">{rules.filter(r => r.category === 'custom').length}</p>
              <p className="text-xs text-null-muted">Custom</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
