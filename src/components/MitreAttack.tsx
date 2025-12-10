import { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Target, Upload, Download, FileText, Hash, Lock, Archive,
  ChevronRight, ChevronDown, AlertTriangle, Shield, Bug, Brain,
  Trash2, CheckCircle2, Clock, Play, Zap
} from 'lucide-react'

interface ThreatItem {
  id: string
  type: 'ioc' | 'log' | 'file' | 'threat'
  name: string
  content: string
  sha256?: string
  timestamp: Date
  status: 'pending' | 'analyzing' | 'qualified' | 'dismissed'
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  mitreTechniques?: string[]
  agentNotes?: string
}

const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', color: 'from-indigo-900 to-indigo-700' },
  { id: 'TA0042', name: 'Resource Development', color: 'from-purple-900 to-purple-700' },
  { id: 'TA0001', name: 'Initial Access', color: 'from-violet-900 to-violet-700' },
  { id: 'TA0002', name: 'Execution', color: 'from-fuchsia-900 to-fuchsia-700' },
  { id: 'TA0003', name: 'Persistence', color: 'from-pink-900 to-pink-700' },
  { id: 'TA0004', name: 'Privilege Escalation', color: 'from-rose-900 to-rose-700' },
  { id: 'TA0005', name: 'Defense Evasion', color: 'from-red-900 to-red-700' },
  { id: 'TA0006', name: 'Credential Access', color: 'from-orange-900 to-orange-700' },
  { id: 'TA0007', name: 'Discovery', color: 'from-amber-900 to-amber-700' },
  { id: 'TA0008', name: 'Lateral Movement', color: 'from-yellow-900 to-yellow-700' },
  { id: 'TA0009', name: 'Collection', color: 'from-lime-900 to-lime-700' },
  { id: 'TA0011', name: 'Command and Control', color: 'from-green-900 to-green-700' },
  { id: 'TA0010', name: 'Exfiltration', color: 'from-teal-900 to-teal-700' },
  { id: 'TA0040', name: 'Impact', color: 'from-cyan-900 to-cyan-700' },
]

const SAMPLE_TECHNIQUES = {
  'TA0001': ['T1566 Phishing', 'T1190 Exploit Public-Facing', 'T1133 External Remote Services'],
  'TA0002': ['T1059 Command & Scripting', 'T1047 Windows Management', 'T1053 Scheduled Task'],
  'TA0003': ['T1547 Boot/Logon Autostart', 'T1053 Scheduled Task', 'T1136 Create Account'],
  'TA0005': ['T1070 Indicator Removal', 'T1036 Masquerading', 'T1027 Obfuscated Files'],
  'TA0006': ['T1110 Brute Force', 'T1003 OS Credential Dump', 'T1555 Password Stores'],
  'TA0008': ['T1021 Remote Services', 'T1550 Alternate Auth', 'T1072 Software Deploy'],
  'TA0011': ['T1071 Application Layer', 'T1095 Non-App Layer', 'T1572 Tunneling'],
}

async function calculateSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer()
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

export default function MitreAttack() {
  const [threats, setThreats] = useState<ThreatItem[]>([])
  const [expandedTactic, setExpandedTactic] = useState<string | null>('TA0001')
  const [selectedThreat, setSelectedThreat] = useState<ThreatItem | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileDrop = async (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)

    const files = Array.from(e.dataTransfer.files)
    for (const file of files) {
      const sha256 = await calculateSha256(file)
      const content = file.type.startsWith('text/') ? await file.text() : `[Binary file: ${file.name}]`

      const newThreat: ThreatItem = {
        id: Date.now().toString() + Math.random(),
        type: file.name.endsWith('.log') ? 'log' : 'file',
        name: file.name,
        content,
        sha256,
        timestamp: new Date(),
        status: 'pending'
      }
      setThreats(prev => [newThreat, ...prev])
    }
  }

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return
    const files = Array.from(e.target.files)
    for (const file of files) {
      const sha256 = await calculateSha256(file)
      const content = file.type.startsWith('text/') ? await file.text() : `[Binary file: ${file.name}]`

      const newThreat: ThreatItem = {
        id: Date.now().toString() + Math.random(),
        type: file.name.endsWith('.log') ? 'log' : 'file',
        name: file.name,
        content,
        sha256,
        timestamp: new Date(),
        status: 'pending'
      }
      setThreats(prev => [newThreat, ...prev])
    }
  }

  const addIOC = (ioc: string) => {
    const newThreat: ThreatItem = {
      id: Date.now().toString(),
      type: 'ioc',
      name: ioc.includes('.') ? 'Domain/IP' : 'Hash/String',
      content: ioc,
      timestamp: new Date(),
      status: 'pending'
    }
    setThreats(prev => [newThreat, ...prev])
  }

  const analyzeWithAgent = async (threat: ThreatItem) => {
    setThreats(prev => prev.map(t =>
      t.id === threat.id ? { ...t, status: 'analyzing' } : t
    ))

    // Simulate agent analysis
    await new Promise(r => setTimeout(r, 2000))

    const techniques = ['T1059.001', 'T1071.001', 'T1110']
    const severity: ThreatItem['severity'] = Math.random() > 0.5 ? 'high' : 'medium'

    setThreats(prev => prev.map(t =>
      t.id === threat.id ? {
        ...t,
        status: 'qualified',
        severity,
        mitreTechniques: techniques,
        agentNotes: 'Agent analysis complete. Potential indicators of compromise detected. Recommend further investigation.'
      } : t
    ))
  }

  const exportPackage = async () => {
    const qualifiedThreats = threats.filter(t => t.status === 'qualified')
    const exportData = {
      timestamp: new Date().toISOString(),
      threats: qualifiedThreats,
      summary: {
        total: qualifiedThreats.length,
        critical: qualifiedThreats.filter(t => t.severity === 'critical').length,
        high: qualifiedThreats.filter(t => t.severity === 'high').length,
        techniques: [...new Set(qualifiedThreats.flatMap(t => t.mitreTechniques || []))]
      }
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `null-threat-package-${Date.now()}.json`
    a.click()
  }

  return (
    <div className="h-full flex overflow-hidden">
      {/* Left panel - Threat ladder */}
      <div className="w-80 border-r border-null-border flex flex-col bg-null-surface/30">
        {/* Upload zone */}
        <div className="p-3 border-b border-null-border">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`
              p-4 border-2 border-dashed rounded-lg cursor-pointer transition-all text-center
              ${dragOver
                ? 'border-null-primary bg-null-primary/10'
                : 'border-null-border hover:border-null-primary/50'}
            `}
          >
            <Upload className="w-6 h-6 mx-auto text-null-muted mb-2" />
            <p className="text-sm text-null-muted">Drop logs, IOCs, threats</p>
            <p className="text-xs text-null-muted mt-1">or click to browse</p>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>
        </div>

        {/* Threat list */}
        <div className="flex-1 overflow-y-auto p-2 space-y-2">
          {threats.length === 0 && (
            <div className="text-center py-8 text-null-muted">
              <Target className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No threats uploaded</p>
              <p className="text-xs mt-1">Drop files to analyze</p>
            </div>
          )}

          {threats.map((threat) => (
            <motion.div
              key={threat.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`
                p-3 rounded-lg border cursor-pointer transition-all
                ${selectedThreat?.id === threat.id
                  ? 'bg-null-primary/10 border-null-primary/30'
                  : 'bg-null-bg/50 border-null-border hover:border-null-primary/30'}
              `}
              onClick={() => setSelectedThreat(threat)}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  {threat.type === 'log' ? <FileText className="w-4 h-4 text-cyan-400" /> :
                   threat.type === 'ioc' ? <Bug className="w-4 h-4 text-red-400" /> :
                   <Archive className="w-4 h-4 text-yellow-400" />}
                  <span className="text-sm text-null-text truncate max-w-[150px]">{threat.name}</span>
                </div>
                {threat.status === 'analyzing' && <Clock className="w-4 h-4 text-null-warning animate-spin" />}
                {threat.status === 'qualified' && <CheckCircle2 className="w-4 h-4 text-null-success" />}
              </div>

              {threat.sha256 && (
                <div className="flex items-center gap-1 mt-2 text-xs text-null-muted">
                  <Hash className="w-3 h-3" />
                  <span className="font-mono truncate">{threat.sha256.slice(0, 16)}...</span>
                </div>
              )}

              {threat.severity && (
                <div className={`
                  mt-2 text-xs px-2 py-0.5 rounded inline-block
                  ${threat.severity === 'critical' ? 'bg-null-danger/20 text-null-danger' :
                    threat.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    'bg-null-warning/20 text-null-warning'}
                `}>
                  {threat.severity}
                </div>
              )}

              {threat.status === 'pending' && (
                <button
                  onClick={(e) => { e.stopPropagation(); analyzeWithAgent(threat) }}
                  className="mt-2 w-full flex items-center justify-center gap-1 px-2 py-1.5 rounded bg-null-primary/20 text-null-primary text-xs hover:bg-null-primary/30"
                >
                  <Brain className="w-3 h-3" />
                  Analyze with Agent
                </button>
              )}
            </motion.div>
          ))}
        </div>

        {/* Actions */}
        <div className="p-3 border-t border-null-border space-y-2">
          <button
            onClick={exportPackage}
            disabled={threats.filter(t => t.status === 'qualified').length === 0}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded bg-null-primary/20 text-null-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
            Export Package (SHA256 + ZIP)
          </button>
          <button className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded bg-null-border text-null-muted hover:text-null-text">
            <Lock className="w-4 h-4" />
            Encrypt & Store
          </button>
        </div>
      </div>

      {/* Right panel - MITRE Matrix */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Target className="w-6 h-6 text-red-400" />
            <div>
              <h2 className="font-display text-lg">MITRE ATT&CK Navigator</h2>
              <p className="text-xs text-null-muted">Enterprise Matrix v14</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs px-2 py-1 rounded bg-null-success/20 text-null-success">
              {threats.filter(t => t.mitreTechniques?.length).length} mapped techniques
            </span>
          </div>
        </div>

        {/* Tactic ladder */}
        <div className="space-y-2">
          {TACTICS.map((tactic) => {
            const isExpanded = expandedTactic === tactic.id
            const techniques = SAMPLE_TECHNIQUES[tactic.id as keyof typeof SAMPLE_TECHNIQUES] || []
            const hasHits = threats.some(t =>
              t.mitreTechniques?.some(tech => techniques.some(tt => tt.startsWith(tech.split('.')[0])))
            )

            return (
              <div key={tactic.id} className="rounded-lg overflow-hidden border border-null-border">
                <button
                  onClick={() => setExpandedTactic(isExpanded ? null : tactic.id)}
                  className={`
                    w-full flex items-center justify-between p-3 bg-gradient-to-r ${tactic.color}
                  `}
                >
                  <div className="flex items-center gap-3">
                    {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    <span className="font-display text-sm">{tactic.id}</span>
                    <span className="text-sm opacity-80">{tactic.name}</span>
                  </div>
                  {hasHits && (
                    <span className="text-xs px-2 py-0.5 rounded bg-null-danger/50 text-white">
                      DETECTED
                    </span>
                  )}
                </button>

                <AnimatePresence>
                  {isExpanded && techniques.length > 0 && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="bg-null-bg/50"
                    >
                      <div className="p-3 grid grid-cols-3 gap-2">
                        {techniques.map((tech, i) => {
                          const techId = tech.split(' ')[0]
                          const isHit = threats.some(t =>
                            t.mitreTechniques?.some(mt => mt.startsWith(techId.split('.')[0]))
                          )

                          return (
                            <div
                              key={i}
                              className={`
                                p-2 rounded text-xs border
                                ${isHit
                                  ? 'bg-null-danger/20 border-null-danger/30 text-null-danger'
                                  : 'bg-null-surface/50 border-null-border text-null-muted'}
                              `}
                            >
                              {tech}
                            </div>
                          )
                        })}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )
          })}
        </div>

        {/* Selected threat details */}
        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-6 p-4 rounded-lg border border-null-border bg-null-surface/30"
          >
            <h3 className="font-display text-sm mb-3">Selected: {selectedThreat.name}</h3>

            {selectedThreat.agentNotes && (
              <div className="p-3 rounded bg-null-bg/50 border border-null-border mb-3">
                <div className="flex items-center gap-2 mb-2">
                  <Brain className="w-4 h-4 text-purple-400" />
                  <span className="text-xs text-purple-400 font-medium">Agent Analysis</span>
                </div>
                <p className="text-sm text-null-text">{selectedThreat.agentNotes}</p>
              </div>
            )}

            {selectedThreat.mitreTechniques && (
              <div className="flex flex-wrap gap-2">
                {selectedThreat.mitreTechniques.map((tech) => (
                  <span key={tech} className="px-2 py-1 rounded bg-red-500/20 text-red-400 text-xs font-mono">
                    {tech}
                  </span>
                ))}
              </div>
            )}

            {selectedThreat.sha256 && (
              <div className="mt-3 p-2 rounded bg-null-bg/50 font-mono text-xs text-null-muted break-all">
                SHA256: {selectedThreat.sha256}
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  )
}
