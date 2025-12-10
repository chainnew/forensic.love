import { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  FileSearch, Filter, ArrowUpDown, ChevronDown, ChevronRight,
  AlertTriangle, Bug, Info, AlertCircle, Download, Upload, Search, X
} from 'lucide-react'

interface LogEntry {
  id: string
  timestamp: string
  source: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  message: string
  raw: string
  fields: Record<string, string>
  mitre?: string
}

const SAMPLE_LOGS: LogEntry[] = [
  {
    id: '1',
    timestamp: '2025-12-10T14:32:15.123Z',
    source: 'Windows Security',
    severity: 'critical',
    category: 'Authentication',
    message: 'Failed login attempt with privileged account Administrator from 192.168.1.100',
    raw: 'Dec 10 14:32:15 DC-01 Security[4625]: An account failed to log on. Subject: Security ID: NULL SID...',
    fields: { user: 'Administrator', source_ip: '192.168.1.100', event_id: '4625' },
    mitre: 'T1110'
  },
  {
    id: '2',
    timestamp: '2025-12-10T14:31:42.456Z',
    source: 'Sysmon',
    severity: 'high',
    category: 'Process',
    message: 'PowerShell executed encoded command with network connection',
    raw: 'Dec 10 14:31:42 WS-05 Sysmon[1]: Process Create: powershell.exe -enc aQBlAHgA...',
    fields: { process: 'powershell.exe', parent: 'cmd.exe', command: '-enc aQBlAHgA...' },
    mitre: 'T1059.001'
  },
  {
    id: '3',
    timestamp: '2025-12-10T14:30:18.789Z',
    source: 'Firewall',
    severity: 'medium',
    category: 'Network',
    message: 'Outbound connection to known C2 IP blocked',
    raw: 'Dec 10 14:30:18 FW-01 DROP: SRC=10.0.0.45 DST=185.234.72.123 PROTO=TCP DPT=443',
    fields: { src_ip: '10.0.0.45', dst_ip: '185.234.72.123', dst_port: '443', action: 'DROP' },
    mitre: 'T1071.001'
  },
  {
    id: '4',
    timestamp: '2025-12-10T14:29:05.321Z',
    source: 'DNS',
    severity: 'high',
    category: 'Network',
    message: 'DNS query to suspicious domain: evil.malware-domain.ru',
    raw: 'Dec 10 14:29:05 DNS-01 query: evil.malware-domain.ru A IN 10.0.0.33',
    fields: { query: 'evil.malware-domain.ru', type: 'A', client: '10.0.0.33' },
    mitre: 'T1071.004'
  },
  {
    id: '5',
    timestamp: '2025-12-10T14:28:33.654Z',
    source: 'Web Proxy',
    severity: 'low',
    category: 'Network',
    message: 'User accessed blocked category: Gambling',
    raw: 'Dec 10 14:28:33 PROXY-01 BLOCK: user=jsmith url=casino-games.com category=Gambling',
    fields: { user: 'jsmith', url: 'casino-games.com', category: 'Gambling', action: 'BLOCK' }
  },
  {
    id: '6',
    timestamp: '2025-12-10T14:27:12.987Z',
    source: 'Linux auditd',
    severity: 'info',
    category: 'System',
    message: 'User sudo command executed successfully',
    raw: 'Dec 10 14:27:12 SRV-DB audit[12345]: USER_CMD pid=12345 uid=1001 user=dbadmin command=/usr/bin/systemctl restart postgresql',
    fields: { user: 'dbadmin', command: 'systemctl restart postgresql', result: 'success' }
  },
  {
    id: '7',
    timestamp: '2025-12-10T14:26:45.147Z',
    source: 'IDS/Suricata',
    severity: 'critical',
    category: 'Intrusion',
    message: 'ET MALWARE Cobalt Strike Beacon C2 Traffic Detected',
    raw: 'Dec 10 14:26:45 IDS-01 [1:2027865:3] ET MALWARE Cobalt Strike Beacon C2 Traffic',
    fields: { signature: 'ET MALWARE Cobalt Strike', src_ip: '10.0.0.45', dst_ip: '185.234.72.123' },
    mitre: 'T1071.001'
  },
  {
    id: '8',
    timestamp: '2025-12-10T14:25:30.852Z',
    source: 'Windows Security',
    severity: 'high',
    category: 'Privilege',
    message: 'User added to Domain Admins group',
    raw: 'Dec 10 14:25:30 DC-01 Security[4728]: A member was added to a security-enabled global group. Group Name: Domain Admins',
    fields: { target_user: 'compromised_user', group: 'Domain Admins', by_user: 'admin' },
    mitre: 'T1098'
  }
]

const SEVERITY_CONFIG = {
  critical: { icon: Bug, color: 'text-null-danger', bg: 'bg-null-danger/20' },
  high: { icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-400/20' },
  medium: { icon: AlertCircle, color: 'text-null-warning', bg: 'bg-null-warning/20' },
  low: { icon: Info, color: 'text-null-info', bg: 'bg-null-info/20' },
  info: { icon: Info, color: 'text-null-muted', bg: 'bg-null-muted/20' }
}

export default function LogViewer() {
  const [logs] = useState<LogEntry[]>(SAMPLE_LOGS)
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string[]>([])
  const [sortField, setSortField] = useState<'timestamp' | 'severity'>('timestamp')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set())

  const filteredLogs = useMemo(() => {
    let result = [...logs]

    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      result = result.filter(log =>
        log.message.toLowerCase().includes(q) ||
        log.source.toLowerCase().includes(q) ||
        log.raw.toLowerCase().includes(q) ||
        Object.values(log.fields).some(v => v.toLowerCase().includes(q))
      )
    }

    if (severityFilter.length > 0) {
      result = result.filter(log => severityFilter.includes(log.severity))
    }

    result.sort((a, b) => {
      if (sortField === 'timestamp') {
        return sortDir === 'desc'
          ? new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          : new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      }
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return sortDir === 'desc'
        ? severityOrder[a.severity] - severityOrder[b.severity]
        : severityOrder[b.severity] - severityOrder[a.severity]
    })

    return result
  }, [logs, searchQuery, severityFilter, sortField, sortDir])

  const toggleExpand = (id: string) => {
    setExpandedLogs(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleSeverityFilter = (sev: string) => {
    setSeverityFilter(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    )
  }

  return (
    <div className="h-full flex">
      {/* Main log list */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="p-3 border-b border-null-border bg-null-surface/30 flex items-center gap-3">
          <div className="flex items-center gap-2 flex-1">
            <Search className="w-4 h-4 text-null-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search logs..."
              className="flex-1 bg-null-bg/50 border border-null-border rounded px-3 py-1.5 text-sm text-null-text placeholder:text-null-muted outline-none focus:border-null-primary/50"
            />
          </div>

          {/* Severity filters */}
          <div className="flex items-center gap-1">
            {Object.entries(SEVERITY_CONFIG).map(([sev, config]) => (
              <button
                key={sev}
                onClick={() => toggleSeverityFilter(sev)}
                className={`
                  px-2 py-1 rounded text-xs border transition-all
                  ${severityFilter.includes(sev)
                    ? `${config.bg} ${config.color} border-current`
                    : 'border-null-border text-null-muted hover:border-null-primary/30'}
                `}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Sort */}
          <button
            onClick={() => setSortDir(d => d === 'asc' ? 'desc' : 'asc')}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded border border-null-border text-null-muted hover:text-null-text"
          >
            <ArrowUpDown className="w-4 h-4" />
            <span className="text-xs">{sortDir === 'desc' ? 'Newest' : 'Oldest'}</span>
          </button>

          {/* Import/Export */}
          <div className="flex items-center gap-1">
            <button className="p-1.5 rounded border border-null-border text-null-muted hover:text-null-text">
              <Upload className="w-4 h-4" />
            </button>
            <button className="p-1.5 rounded border border-null-border text-null-muted hover:text-null-text">
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Log entries */}
        <div className="flex-1 overflow-y-auto">
          {filteredLogs.map((log) => {
            const config = SEVERITY_CONFIG[log.severity]
            const Icon = config.icon
            const isExpanded = expandedLogs.has(log.id)

            return (
              <motion.div
                key={log.id}
                layout
                className="border-b border-null-border/50 hover:bg-null-surface/30"
              >
                <div
                  className="flex items-start gap-3 p-3 cursor-pointer"
                  onClick={() => toggleExpand(log.id)}
                >
                  <button className="mt-0.5">
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-null-muted" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-null-muted" />
                    )}
                  </button>

                  <div className={`p-1 rounded ${config.bg}`}>
                    <Icon className={`w-4 h-4 ${config.color}`} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-null-muted font-mono">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-null-border text-null-muted">
                        {log.source}
                      </span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-null-border/50 text-null-muted">
                        {log.category}
                      </span>
                      {log.mitre && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-mono">
                          {log.mitre}
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-null-text mt-1 truncate">{log.message}</p>
                  </div>
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="px-3 pb-3 ml-[52px]"
                  >
                    {/* Parsed fields */}
                    <div className="mb-3">
                      <p className="text-xs text-null-muted mb-1.5">Parsed Fields:</p>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(log.fields).map(([key, value]) => (
                          <div key={key} className="px-2 py-1 rounded bg-null-bg/50 border border-null-border/50">
                            <span className="text-xs text-cyan-400">{key}: </span>
                            <span className="text-xs text-null-text font-mono">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Raw log */}
                    <div>
                      <p className="text-xs text-null-muted mb-1.5">Raw Log:</p>
                      <pre className="text-xs font-mono text-null-text bg-null-bg/50 p-2 rounded border border-null-border/50 overflow-x-auto">
                        {log.raw}
                      </pre>
                    </div>

                    <div className="mt-2 flex gap-2">
                      <button className="text-xs px-2 py-1 rounded bg-null-primary/20 text-null-primary">
                        Add to Investigation
                      </button>
                      <button className="text-xs px-2 py-1 rounded bg-null-border text-null-muted">
                        Copy Raw
                      </button>
                    </div>
                  </motion.div>
                )}
              </motion.div>
            )
          })}
        </div>

        {/* Stats bar */}
        <div className="p-2 border-t border-null-border bg-null-surface/30 flex items-center justify-between text-xs text-null-muted">
          <span>{filteredLogs.length} logs displayed</span>
          <div className="flex items-center gap-3">
            <span className="text-null-danger">{logs.filter(l => l.severity === 'critical').length} critical</span>
            <span className="text-orange-400">{logs.filter(l => l.severity === 'high').length} high</span>
            <span className="text-null-warning">{logs.filter(l => l.severity === 'medium').length} medium</span>
          </div>
        </div>
      </div>
    </div>
  )
}
