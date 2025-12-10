import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Clock, Filter, Download, ZoomIn, ZoomOut,
  FileText, Terminal, Network, User, AlertTriangle, Shield
} from 'lucide-react'

interface TimelineEvent {
  id: string
  timestamp: Date
  type: 'process' | 'network' | 'file' | 'auth' | 'alert' | 'system'
  source: string
  description: string
  details: Record<string, string>
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  mitre?: string
}

const SAMPLE_EVENTS: TimelineEvent[] = [
  {
    id: '1',
    timestamp: new Date('2025-12-10T14:32:15'),
    type: 'alert',
    source: 'IDS',
    description: 'Cobalt Strike beacon detected',
    details: { signature: 'ET MALWARE Cobalt Strike', src_ip: '10.0.0.45', dst_ip: '185.234.72.123' },
    severity: 'critical',
    mitre: 'T1071.001'
  },
  {
    id: '2',
    timestamp: new Date('2025-12-10T14:31:42'),
    type: 'process',
    source: 'Sysmon',
    description: 'PowerShell encoded command execution',
    details: { process: 'powershell.exe', parent: 'cmd.exe', user: 'DOMAIN\\admin' },
    severity: 'high',
    mitre: 'T1059.001'
  },
  {
    id: '3',
    timestamp: new Date('2025-12-10T14:30:18'),
    type: 'network',
    source: 'Firewall',
    description: 'Outbound connection to C2 blocked',
    details: { src_ip: '10.0.0.45', dst_ip: '185.234.72.123', dst_port: '443' },
    severity: 'high',
    mitre: 'T1071.001'
  },
  {
    id: '4',
    timestamp: new Date('2025-12-10T14:29:05'),
    type: 'network',
    source: 'DNS',
    description: 'DNS query to suspicious domain',
    details: { query: 'evil.malware-domain.ru', type: 'A', client: '10.0.0.33' },
    severity: 'medium',
    mitre: 'T1071.004'
  },
  {
    id: '5',
    timestamp: new Date('2025-12-10T14:28:30'),
    type: 'file',
    source: 'EDR',
    description: 'Suspicious file written to disk',
    details: { path: 'C:\\Users\\Public\\update.exe', hash: 'abc123...', size: '245KB' },
    severity: 'high',
    mitre: 'T1105'
  },
  {
    id: '6',
    timestamp: new Date('2025-12-10T14:27:15'),
    type: 'auth',
    source: 'Windows Security',
    description: 'User added to Domain Admins',
    details: { target_user: 'compromised_user', group: 'Domain Admins', by_user: 'admin' },
    severity: 'critical',
    mitre: 'T1098'
  },
  {
    id: '7',
    timestamp: new Date('2025-12-10T14:26:00'),
    type: 'process',
    source: 'Sysmon',
    description: 'LSASS memory access detected',
    details: { target: 'lsass.exe', source_process: 'mimikatz.exe', access: 'READ' },
    severity: 'critical',
    mitre: 'T1003.001'
  },
  {
    id: '8',
    timestamp: new Date('2025-12-10T14:25:30'),
    type: 'auth',
    source: 'Windows Security',
    description: 'Pass-the-hash authentication',
    details: { user: 'Administrator', logon_type: '9', src_ip: '10.0.0.45' },
    severity: 'critical',
    mitre: 'T1550.002'
  },
]

const TYPE_CONFIG = {
  process: { icon: Terminal, color: 'text-purple-400', bg: 'bg-purple-400' },
  network: { icon: Network, color: 'text-cyan-400', bg: 'bg-cyan-400' },
  file: { icon: FileText, color: 'text-yellow-400', bg: 'bg-yellow-400' },
  auth: { icon: User, color: 'text-green-400', bg: 'bg-green-400' },
  alert: { icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-400' },
  system: { icon: Shield, color: 'text-blue-400', bg: 'bg-blue-400' },
}

export default function ForensicTimeline() {
  const [events] = useState<TimelineEvent[]>(SAMPLE_EVENTS)
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null)
  const [typeFilter, setTypeFilter] = useState<string[]>([])
  const [zoom, setZoom] = useState(1)

  const filteredEvents = events.filter(e =>
    typeFilter.length === 0 || typeFilter.includes(e.type)
  ).sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())

  const toggleTypeFilter = (type: string) => {
    setTypeFilter(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="p-3 border-b border-null-border bg-null-surface/30 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Clock className="w-5 h-5 text-null-primary" />
          <span className="font-display text-sm">Forensic Timeline</span>
          <span className="text-xs text-null-muted">CASE-2025-001</span>
        </div>

        <div className="flex items-center gap-2">
          {/* Type filters */}
          {Object.entries(TYPE_CONFIG).map(([type, config]) => {
            const Icon = config.icon
            return (
              <button
                key={type}
                onClick={() => toggleTypeFilter(type)}
                className={`
                  p-1.5 rounded border transition-all
                  ${typeFilter.includes(type)
                    ? `${config.color} border-current bg-current/10`
                    : 'border-null-border text-null-muted hover:border-null-primary/30'}
                `}
              >
                <Icon className="w-4 h-4" />
              </button>
            )
          })}

          <div className="w-px h-6 bg-null-border mx-2" />

          {/* Zoom controls */}
          <button
            onClick={() => setZoom(z => Math.max(0.5, z - 0.25))}
            className="p-1.5 rounded border border-null-border text-null-muted hover:text-null-text"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <span className="text-xs text-null-muted w-12 text-center">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom(z => Math.min(2, z + 0.25))}
            className="p-1.5 rounded border border-null-border text-null-muted hover:text-null-text"
          >
            <ZoomIn className="w-4 h-4" />
          </button>

          <button className="p-1.5 rounded border border-null-border text-null-muted hover:text-null-text">
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Timeline content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Timeline visualization */}
        <div className="flex-1 overflow-y-auto p-4" style={{ fontSize: `${zoom}rem` }}>
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-null-border" />

            {/* Events */}
            <div className="space-y-4">
              {filteredEvents.map((event, i) => {
                const config = TYPE_CONFIG[event.type]
                const Icon = config.icon

                return (
                  <motion.div
                    key={event.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className={`
                      relative flex gap-4 cursor-pointer
                      ${selectedEvent?.id === event.id ? 'opacity-100' : 'opacity-80 hover:opacity-100'}
                    `}
                    onClick={() => setSelectedEvent(event)}
                  >
                    {/* Timeline node */}
                    <div className={`
                      relative z-10 w-4 h-4 rounded-full ${config.bg}
                      flex items-center justify-center flex-shrink-0 mt-1
                    `}>
                      <div className="w-2 h-2 rounded-full bg-null-bg" />
                    </div>

                    {/* Event card */}
                    <div className={`
                      flex-1 p-3 rounded-lg border transition-all
                      ${selectedEvent?.id === event.id
                        ? 'bg-null-surface border-null-primary/30'
                        : 'bg-null-bg/50 border-null-border hover:border-null-primary/20'}
                    `}>
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-4 h-4 ${config.color}`} />
                          <span className="text-sm font-medium text-null-text">{event.description}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {event.mitre && (
                            <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-mono">
                              {event.mitre}
                            </span>
                          )}
                          <span className={`
                            text-xs px-1.5 py-0.5 rounded
                            ${event.severity === 'critical' ? 'bg-null-danger/20 text-null-danger' :
                              event.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                              event.severity === 'medium' ? 'bg-null-warning/20 text-null-warning' :
                              'bg-null-muted/20 text-null-muted'}
                          `}>
                            {event.severity}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 mt-2 text-xs text-null-muted">
                        <span>{event.timestamp.toLocaleTimeString()}</span>
                        <span className="px-1.5 py-0.5 rounded bg-null-border">{event.source}</span>
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Details panel */}
        {selectedEvent && (
          <motion.div
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            className="w-80 border-l border-null-border bg-null-surface/50 p-4 overflow-y-auto"
          >
            <h3 className="font-display text-sm mb-4">Event Details</h3>

            <div className="space-y-4">
              <div>
                <label className="text-xs text-null-muted">Timestamp</label>
                <p className="text-sm text-null-text font-mono">
                  {selectedEvent.timestamp.toISOString()}
                </p>
              </div>

              <div>
                <label className="text-xs text-null-muted">Type</label>
                <p className="text-sm text-null-text capitalize">{selectedEvent.type}</p>
              </div>

              <div>
                <label className="text-xs text-null-muted">Source</label>
                <p className="text-sm text-null-text">{selectedEvent.source}</p>
              </div>

              <div>
                <label className="text-xs text-null-muted">Description</label>
                <p className="text-sm text-null-text">{selectedEvent.description}</p>
              </div>

              {selectedEvent.mitre && (
                <div>
                  <label className="text-xs text-null-muted">MITRE ATT&CK</label>
                  <p className="text-sm text-red-400 font-mono">{selectedEvent.mitre}</p>
                </div>
              )}

              <div>
                <label className="text-xs text-null-muted mb-2 block">Details</label>
                <div className="space-y-1">
                  {Object.entries(selectedEvent.details).map(([key, value]) => (
                    <div key={key} className="px-2 py-1.5 rounded bg-null-bg/50 border border-null-border/50">
                      <span className="text-xs text-cyan-400">{key}: </span>
                      <span className="text-xs text-null-text font-mono">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-4 border-t border-null-border space-y-2">
                <button className="w-full px-3 py-2 rounded bg-null-primary/20 text-null-primary text-sm">
                  Add to Evidence
                </button>
                <button className="w-full px-3 py-2 rounded bg-null-border text-null-muted text-sm">
                  Create Link
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </div>

      {/* Stats bar */}
      <div className="p-2 border-t border-null-border bg-null-surface/30 flex items-center justify-between text-xs text-null-muted">
        <span>{filteredEvents.length} events displayed</span>
        <div className="flex items-center gap-3">
          <span className="text-null-danger">{events.filter(e => e.severity === 'critical').length} critical</span>
          <span className="text-orange-400">{events.filter(e => e.severity === 'high').length} high</span>
          <span className="text-null-warning">{events.filter(e => e.severity === 'medium').length} medium</span>
        </div>
      </div>
    </div>
  )
}
