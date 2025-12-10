import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Globe, Server, Shield, AlertTriangle, RefreshCw, Plus,
  ExternalLink, Lock, Unlock, Eye, Search, Filter
} from 'lucide-react'

interface Asset {
  id: string
  type: 'domain' | 'ip' | 'service' | 'cert'
  value: string
  status: 'secure' | 'warning' | 'critical' | 'unknown'
  lastScan: Date
  findings: string[]
  ports?: number[]
  technologies?: string[]
}

const SAMPLE_ASSETS: Asset[] = [
  {
    id: '1',
    type: 'domain',
    value: 'api.example.com',
    status: 'secure',
    lastScan: new Date('2025-12-10T12:00:00'),
    findings: ['Valid SSL certificate', 'HSTS enabled', 'No exposed admin panels'],
    technologies: ['nginx', 'Node.js', 'React']
  },
  {
    id: '2',
    type: 'domain',
    value: 'admin.example.com',
    status: 'warning',
    lastScan: new Date('2025-12-10T11:30:00'),
    findings: ['Certificate expires in 15 days', 'Missing CSP header'],
    technologies: ['Apache', 'PHP', 'WordPress']
  },
  {
    id: '3',
    type: 'ip',
    value: '203.0.113.50',
    status: 'critical',
    lastScan: new Date('2025-12-10T10:00:00'),
    findings: ['SSH exposed to internet', 'Outdated OpenSSH version', 'Failed login attempts detected'],
    ports: [22, 80, 443, 3306]
  },
  {
    id: '4',
    type: 'ip',
    value: '198.51.100.25',
    status: 'warning',
    lastScan: new Date('2025-12-10T09:45:00'),
    findings: ['Database port exposed', 'Missing rate limiting'],
    ports: [22, 443, 5432]
  },
  {
    id: '5',
    type: 'service',
    value: 'PostgreSQL (198.51.100.25:5432)',
    status: 'warning',
    lastScan: new Date('2025-12-10T09:00:00'),
    findings: ['External access allowed', 'Default SSL certificate'],
    technologies: ['PostgreSQL 14.2']
  },
  {
    id: '6',
    type: 'cert',
    value: '*.example.com (Let\'s Encrypt)',
    status: 'secure',
    lastScan: new Date('2025-12-10T08:00:00'),
    findings: ['Valid until 2026-03-10', 'TLS 1.3 supported']
  },
]

const STATUS_CONFIG = {
  secure: { color: 'text-null-success', bg: 'bg-null-success/20', icon: Shield },
  warning: { color: 'text-null-warning', bg: 'bg-null-warning/20', icon: AlertTriangle },
  critical: { color: 'text-null-danger', bg: 'bg-null-danger/20', icon: AlertTriangle },
  unknown: { color: 'text-null-muted', bg: 'bg-null-muted/20', icon: Eye },
}

const TYPE_ICONS = {
  domain: Globe,
  ip: Server,
  service: Lock,
  cert: Shield,
}

export default function AttackSurface() {
  const [assets] = useState<Asset[]>(SAMPLE_ASSETS)
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const [typeFilter, setTypeFilter] = useState<string[]>([])
  const [statusFilter, setStatusFilter] = useState<string[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [scanning, setScanning] = useState(false)

  const filteredAssets = assets.filter(asset => {
    if (typeFilter.length > 0 && !typeFilter.includes(asset.type)) return false
    if (statusFilter.length > 0 && !statusFilter.includes(asset.status)) return false
    if (searchQuery && !asset.value.toLowerCase().includes(searchQuery.toLowerCase())) return false
    return true
  })

  const runScan = async () => {
    setScanning(true)
    await new Promise(r => setTimeout(r, 3000))
    setScanning(false)
  }

  const stats = {
    total: assets.length,
    secure: assets.filter(a => a.status === 'secure').length,
    warning: assets.filter(a => a.status === 'warning').length,
    critical: assets.filter(a => a.status === 'critical').length,
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-null-border bg-null-surface/30">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Globe className="w-6 h-6 text-orange-400" />
            <div>
              <h2 className="font-display text-lg">Attack Surface Monitor</h2>
              <p className="text-xs text-null-muted">External asset discovery & vulnerability tracking</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={runScan}
              disabled={scanning}
              className="flex items-center gap-2 px-3 py-2 rounded bg-null-primary/20 text-null-primary disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
              {scanning ? 'Scanning...' : 'Run Scan'}
            </button>
            <button className="flex items-center gap-2 px-3 py-2 rounded bg-null-border text-null-muted hover:text-null-text">
              <Plus className="w-4 h-4" />
              Add Asset
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4">
          <div className="p-3 rounded-lg bg-null-bg/50 border border-null-border">
            <p className="text-xs text-null-muted">Total Assets</p>
            <p className="text-2xl font-display text-null-text">{stats.total}</p>
          </div>
          <div className="p-3 rounded-lg bg-null-success/10 border border-null-success/30">
            <p className="text-xs text-null-success">Secure</p>
            <p className="text-2xl font-display text-null-success">{stats.secure}</p>
          </div>
          <div className="p-3 rounded-lg bg-null-warning/10 border border-null-warning/30">
            <p className="text-xs text-null-warning">Warnings</p>
            <p className="text-2xl font-display text-null-warning">{stats.warning}</p>
          </div>
          <div className="p-3 rounded-lg bg-null-danger/10 border border-null-danger/30">
            <p className="text-xs text-null-danger">Critical</p>
            <p className="text-2xl font-display text-null-danger">{stats.critical}</p>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="p-3 border-b border-null-border flex items-center gap-3">
        <div className="flex items-center gap-2 flex-1">
          <Search className="w-4 h-4 text-null-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search assets..."
            className="flex-1 bg-null-bg/50 border border-null-border rounded px-3 py-1.5 text-sm text-null-text placeholder:text-null-muted outline-none focus:border-null-primary/50"
          />
        </div>

        {/* Type filters */}
        <div className="flex items-center gap-1">
          {Object.entries(TYPE_ICONS).map(([type, Icon]) => (
            <button
              key={type}
              onClick={() => setTypeFilter(prev =>
                prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
              )}
              className={`
                px-2 py-1 rounded text-xs border transition-all flex items-center gap-1
                ${typeFilter.includes(type)
                  ? 'bg-null-primary/20 border-null-primary/30 text-null-primary'
                  : 'border-null-border text-null-muted hover:border-null-primary/30'}
              `}
            >
              <Icon className="w-3 h-3" />
              {type}
            </button>
          ))}
        </div>

        {/* Status filters */}
        <div className="flex items-center gap-1">
          {Object.entries(STATUS_CONFIG).map(([status, config]) => (
            <button
              key={status}
              onClick={() => setStatusFilter(prev =>
                prev.includes(status) ? prev.filter(s => s !== status) : [...prev, status]
              )}
              className={`
                px-2 py-1 rounded text-xs border transition-all
                ${statusFilter.includes(status)
                  ? `${config.bg} ${config.color} border-current`
                  : 'border-null-border text-null-muted hover:border-null-primary/30'}
              `}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Asset list */}
        <div className="flex-1 overflow-y-auto p-4">
          <div className="space-y-2">
            {filteredAssets.map((asset, i) => {
              const TypeIcon = TYPE_ICONS[asset.type]
              const statusConfig = STATUS_CONFIG[asset.status]
              const StatusIcon = statusConfig.icon

              return (
                <motion.div
                  key={asset.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className={`
                    p-4 rounded-lg border cursor-pointer transition-all
                    ${selectedAsset?.id === asset.id
                      ? 'bg-null-surface border-null-primary/30'
                      : 'bg-null-bg/50 border-null-border hover:border-null-primary/20'}
                  `}
                  onClick={() => setSelectedAsset(asset)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded ${statusConfig.bg}`}>
                        <TypeIcon className={`w-4 h-4 ${statusConfig.color}`} />
                      </div>
                      <div>
                        <p className="text-sm text-null-text font-mono">{asset.value}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-xs text-null-muted capitalize">{asset.type}</span>
                          {asset.ports && (
                            <span className="text-xs text-null-muted">
                              Ports: {asset.ports.join(', ')}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <StatusIcon className={`w-4 h-4 ${statusConfig.color}`} />
                      <span className={`text-xs px-2 py-0.5 rounded ${statusConfig.bg} ${statusConfig.color} capitalize`}>
                        {asset.status}
                      </span>
                    </div>
                  </div>

                  {/* Findings preview */}
                  <div className="mt-3 flex flex-wrap gap-1">
                    {asset.findings.slice(0, 2).map((finding, j) => (
                      <span key={j} className="text-xs px-2 py-0.5 rounded bg-null-border text-null-muted">
                        {finding}
                      </span>
                    ))}
                    {asset.findings.length > 2 && (
                      <span className="text-xs text-null-muted">+{asset.findings.length - 2} more</span>
                    )}
                  </div>

                  {/* Technologies */}
                  {asset.technologies && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {asset.technologies.map((tech, j) => (
                        <span key={j} className="text-xs px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400">
                          {tech}
                        </span>
                      ))}
                    </div>
                  )}
                </motion.div>
              )
            })}
          </div>
        </div>

        {/* Details panel */}
        {selectedAsset && (
          <motion.div
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            className="w-96 border-l border-null-border bg-null-surface/50 p-4 overflow-y-auto"
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-sm">Asset Details</h3>
              <button className="p-1.5 rounded hover:bg-null-border/50 text-null-muted">
                <ExternalLink className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs text-null-muted">Value</label>
                <p className="text-sm text-null-text font-mono">{selectedAsset.value}</p>
              </div>

              <div>
                <label className="text-xs text-null-muted">Type</label>
                <p className="text-sm text-null-text capitalize">{selectedAsset.type}</p>
              </div>

              <div>
                <label className="text-xs text-null-muted">Status</label>
                <p className={`text-sm capitalize ${STATUS_CONFIG[selectedAsset.status].color}`}>
                  {selectedAsset.status}
                </p>
              </div>

              <div>
                <label className="text-xs text-null-muted">Last Scan</label>
                <p className="text-sm text-null-text">{selectedAsset.lastScan.toLocaleString()}</p>
              </div>

              {selectedAsset.ports && (
                <div>
                  <label className="text-xs text-null-muted">Open Ports</label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedAsset.ports.map(port => (
                      <span key={port} className="text-xs px-2 py-0.5 rounded bg-null-border text-null-text font-mono">
                        {port}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <label className="text-xs text-null-muted mb-2 block">Findings ({selectedAsset.findings.length})</label>
                <div className="space-y-2">
                  {selectedAsset.findings.map((finding, i) => (
                    <div key={i} className="p-2 rounded bg-null-bg/50 border border-null-border/50 text-xs text-null-text">
                      {finding}
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-4 border-t border-null-border space-y-2">
                <button className="w-full px-3 py-2 rounded bg-null-primary/20 text-null-primary text-sm">
                  Run Deep Scan
                </button>
                <button className="w-full px-3 py-2 rounded bg-null-border text-null-muted text-sm">
                  Add to Investigation
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  )
}
