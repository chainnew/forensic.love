import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, AlertTriangle, Eye, Lock, Key, File, Database, Globe,
  Mail, User, CreditCard, Server, Activity, Clock, MapPin, Zap,
  Plus, Trash2, RefreshCw, Copy, CheckCircle, XCircle, Settings,
  ChevronDown, ChevronRight, Bell, Terminal
} from 'lucide-react'

interface Honeytoken {
  id: string
  name: string
  type: 'api_key' | 'password' | 'email' | 'document' | 'database' | 'url' | 'ssh_key' | 'aws_cred'
  value: string
  deployed: boolean
  location: string
  triggers: number
  lastTriggered?: number
  created: number
  notes?: string
}

interface TriggerEvent {
  id: string
  honeytokenId: string
  honeytokenName: string
  type: string
  timestamp: number
  sourceIp: string
  userAgent?: string
  location?: string
  severity: 'critical' | 'high' | 'medium'
  details: Record<string, unknown>
}

const TOKEN_TYPES = {
  'api_key': {
    icon: Key,
    color: 'text-red-400',
    bg: 'bg-red-500/20',
    generator: () => `sk-null-${randomString(32)}`,
    description: 'Fake API key to detect unauthorized access'
  },
  'password': {
    icon: Lock,
    color: 'text-orange-400',
    bg: 'bg-orange-500/20',
    generator: () => `${randomWord()}${randomWord()}${Math.floor(Math.random() * 1000)}!`,
    description: 'Decoy password for credential harvesting detection'
  },
  'email': {
    icon: Mail,
    color: 'text-blue-400',
    bg: 'bg-blue-500/20',
    generator: () => `honeypot-${randomString(8)}@null-spawn.local`,
    description: 'Canary email address for phishing detection'
  },
  'document': {
    icon: File,
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/20',
    generator: () => `CONFIDENTIAL_${randomWord().toUpperCase()}_${Date.now()}.pdf`,
    description: 'Fake sensitive document for exfiltration detection'
  },
  'database': {
    icon: Database,
    color: 'text-purple-400',
    bg: 'bg-purple-500/20',
    generator: () => `mongodb://admin:${randomString(16)}@db.internal:27017/secrets`,
    description: 'Decoy database connection string'
  },
  'url': {
    icon: Globe,
    color: 'text-cyan-400',
    bg: 'bg-cyan-500/20',
    generator: () => `https://admin.null-spawn.local/secret-${randomString(8)}/`,
    description: 'Hidden URL for reconnaissance detection'
  },
  'ssh_key': {
    icon: Terminal,
    color: 'text-green-400',
    bg: 'bg-green-500/20',
    generator: () => `-----BEGIN RSA PRIVATE KEY-----\nHONEYTOKEN_${randomString(40)}\n-----END RSA PRIVATE KEY-----`,
    description: 'Fake SSH key for lateral movement detection'
  },
  'aws_cred': {
    icon: Server,
    color: 'text-pink-400',
    bg: 'bg-pink-500/20',
    generator: () => `AKIA${randomString(16).toUpperCase()}\naws_secret=${randomString(40)}`,
    description: 'Canary AWS credentials for cloud breach detection'
  }
}

function randomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
}

function randomWord(): string {
  const words = ['quantum', 'nebula', 'cipher', 'phantom', 'shadow', 'ghost', 'specter', 'oracle', 'nexus', 'void']
  return words[Math.floor(Math.random() * words.length)]
}

// Demo honeytokens
const DEMO_HONEYTOKENS: Honeytoken[] = [
  {
    id: 'ht-1',
    name: 'Production API Key',
    type: 'api_key',
    value: 'sk-null-7f8e9a2b3c4d5e6f7a8b9c0d1e2f3a4b',
    deployed: true,
    location: '/var/secrets/api.key',
    triggers: 3,
    lastTriggered: Date.now() - 3600000,
    created: Date.now() - 86400000 * 30
  },
  {
    id: 'ht-2',
    name: 'Admin Password',
    type: 'password',
    value: 'QuantumNebula2024!',
    deployed: true,
    location: 'Active Directory - IT Admins Group',
    triggers: 1,
    lastTriggered: Date.now() - 86400000,
    created: Date.now() - 86400000 * 60
  },
  {
    id: 'ht-3',
    name: 'CEO Email Canary',
    type: 'email',
    value: 'ceo.backup@null-spawn.local',
    deployed: true,
    location: 'Exchange GAL',
    triggers: 0,
    created: Date.now() - 86400000 * 15
  },
  {
    id: 'ht-4',
    name: 'AWS Root Credentials',
    type: 'aws_cred',
    value: 'AKIAIOSFODNN7EXAMPLE\naws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    deployed: true,
    location: '~/.aws/credentials',
    triggers: 2,
    lastTriggered: Date.now() - 7200000,
    created: Date.now() - 86400000 * 45
  }
]

// Demo trigger events
const DEMO_EVENTS: TriggerEvent[] = [
  {
    id: 'evt-1',
    honeytokenId: 'ht-1',
    honeytokenName: 'Production API Key',
    type: 'api_key',
    timestamp: Date.now() - 3600000,
    sourceIp: '185.225.69.69',
    userAgent: 'python-requests/2.28.1',
    location: 'Moscow, Russia',
    severity: 'critical',
    details: { endpoint: '/api/v1/users', method: 'GET', response_code: 401 }
  },
  {
    id: 'evt-2',
    honeytokenId: 'ht-4',
    honeytokenName: 'AWS Root Credentials',
    type: 'aws_cred',
    timestamp: Date.now() - 7200000,
    sourceIp: '45.77.65.211',
    userAgent: 'aws-cli/2.9.0',
    location: 'Netherlands',
    severity: 'critical',
    details: { service: 'sts', action: 'GetCallerIdentity' }
  },
  {
    id: 'evt-3',
    honeytokenId: 'ht-2',
    honeytokenName: 'Admin Password',
    type: 'password',
    timestamp: Date.now() - 86400000,
    sourceIp: '192.168.1.100',
    userAgent: 'NTLM',
    location: 'Internal Network',
    severity: 'high',
    details: { target: 'DC01.corp.local', auth_type: 'Kerberos' }
  }
]

export default function MimicHoneytokens() {
  const [honeytokens, setHoneytokens] = useState<Honeytoken[]>(DEMO_HONEYTOKENS)
  const [triggerEvents, setTriggerEvents] = useState<TriggerEvent[]>(DEMO_EVENTS)
  const [selectedToken, setSelectedToken] = useState<Honeytoken | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [newToken, setNewToken] = useState({
    name: '',
    type: 'api_key' as keyof typeof TOKEN_TYPES,
    location: '',
    notes: ''
  })
  const [filter, setFilter] = useState<'all' | 'deployed' | 'triggered'>('all')
  const [expandedEvents, setExpandedEvents] = useState<string[]>([])

  // Simulate real-time events
  useEffect(() => {
    const interval = setInterval(() => {
      // Randomly trigger a honeytoken (demo purposes)
      if (Math.random() < 0.1) {
        const activeTokens = honeytokens.filter(t => t.deployed)
        if (activeTokens.length > 0) {
          const token = activeTokens[Math.floor(Math.random() * activeTokens.length)]
          const newEvent: TriggerEvent = {
            id: `evt-${Date.now()}`,
            honeytokenId: token.id,
            honeytokenName: token.name,
            type: token.type,
            timestamp: Date.now(),
            sourceIp: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            userAgent: ['curl/7.79.1', 'python-requests/2.28.1', 'Go-http-client/1.1'][Math.floor(Math.random() * 3)],
            location: ['Unknown', 'Russia', 'China', 'North Korea'][Math.floor(Math.random() * 4)],
            severity: Math.random() < 0.3 ? 'critical' : Math.random() < 0.6 ? 'high' : 'medium',
            details: { automated: true }
          }

          setTriggerEvents(prev => [newEvent, ...prev].slice(0, 50))
          setHoneytokens(prev => prev.map(t =>
            t.id === token.id ? { ...t, triggers: t.triggers + 1, lastTriggered: Date.now() } : t
          ))
        }
      }
    }, 10000)

    return () => clearInterval(interval)
  }, [honeytokens])

  // Create new honeytoken
  const createHoneytoken = () => {
    const typeConfig = TOKEN_TYPES[newToken.type]
    const token: Honeytoken = {
      id: `ht-${Date.now()}`,
      name: newToken.name,
      type: newToken.type,
      value: typeConfig.generator(),
      deployed: false,
      location: newToken.location,
      triggers: 0,
      created: Date.now(),
      notes: newToken.notes
    }

    setHoneytokens([token, ...honeytokens])
    setNewToken({ name: '', type: 'api_key', location: '', notes: '' })
    setShowCreateModal(false)
  }

  // Toggle deployment
  const toggleDeploy = (id: string) => {
    setHoneytokens(honeytokens.map(t =>
      t.id === id ? { ...t, deployed: !t.deployed } : t
    ))
  }

  // Delete honeytoken
  const deleteToken = (id: string) => {
    setHoneytokens(honeytokens.filter(t => t.id !== id))
    if (selectedToken?.id === id) setSelectedToken(null)
  }

  // Copy value to clipboard
  const copyValue = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  // Filter tokens
  const filteredTokens = honeytokens.filter(t => {
    if (filter === 'deployed') return t.deployed
    if (filter === 'triggered') return t.triggers > 0
    return true
  })

  // Stats
  const stats = {
    total: honeytokens.length,
    deployed: honeytokens.filter(t => t.deployed).length,
    triggered: honeytokens.filter(t => t.triggers > 0).length,
    totalTriggers: honeytokens.reduce((sum, t) => sum + t.triggers, 0)
  }

  return (
    <div className="h-full flex bg-null-bg">
      {/* Left Panel - Honeytokens List */}
      <div className="w-96 border-r border-null-border flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-null-border">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-green-400" />
              <span className="font-display text-null-text">MIMIC</span>
            </div>
            <button
              onClick={() => setShowCreateModal(true)}
              className="p-1.5 rounded bg-green-500/20 text-green-400 hover:bg-green-500/30"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>
          <p className="text-xs text-null-muted">
            Active Defense • Honeytokens & Canary Tokens
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-2 p-3 border-b border-null-border bg-null-surface/30">
          <div className="text-center">
            <div className="text-lg font-mono text-null-text">{stats.total}</div>
            <div className="text-[10px] text-null-muted">Total</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-mono text-green-400">{stats.deployed}</div>
            <div className="text-[10px] text-null-muted">Deployed</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-mono text-orange-400">{stats.triggered}</div>
            <div className="text-[10px] text-null-muted">Triggered</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-mono text-red-400">{stats.totalTriggers}</div>
            <div className="text-[10px] text-null-muted">Alerts</div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex gap-1 p-2 border-b border-null-border">
          {(['all', 'deployed', 'triggered'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`flex-1 px-2 py-1 rounded text-xs ${
                filter === f
                  ? 'bg-green-500/20 text-green-400'
                  : 'text-null-muted hover:bg-null-surface'
              }`}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>

        {/* Token List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-2">
          {filteredTokens.map(token => {
            const config = TOKEN_TYPES[token.type]
            const Icon = config.icon

            return (
              <motion.button
                key={token.id}
                onClick={() => setSelectedToken(token)}
                className={`w-full p-3 rounded-lg text-left transition-all ${
                  selectedToken?.id === token.id
                    ? 'bg-green-500/20 border border-green-500/30'
                    : 'bg-null-surface/50 hover:bg-null-surface border border-transparent'
                }`}
                whileHover={{ scale: 1.01 }}
              >
                <div className="flex items-start gap-3">
                  <div className={`p-1.5 rounded ${config.bg}`}>
                    <Icon className={`w-4 h-4 ${config.color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-null-text truncate">{token.name}</span>
                      {token.deployed ? (
                        <span className="px-1 py-0.5 rounded text-[10px] bg-green-500/20 text-green-400">
                          LIVE
                        </span>
                      ) : (
                        <span className="px-1 py-0.5 rounded text-[10px] bg-null-border text-null-muted">
                          DRAFT
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-null-muted truncate mt-1">
                      {token.location}
                    </div>
                    <div className="flex items-center gap-3 mt-2">
                      <span className={`text-xs ${token.triggers > 0 ? 'text-red-400' : 'text-null-muted'}`}>
                        <Bell className="w-3 h-3 inline mr-1" />
                        {token.triggers} triggers
                      </span>
                      {token.lastTriggered && (
                        <span className="text-[10px] text-null-muted">
                          Last: {new Date(token.lastTriggered).toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </motion.button>
            )
          })}
        </div>
      </div>

      {/* Center Panel - Trigger Events */}
      <div className="flex-1 flex flex-col">
        <div className="p-4 border-b border-null-border bg-null-surface/30">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-red-400 animate-pulse" />
            <span className="font-display text-null-text">Live Trigger Feed</span>
            <span className="ml-auto text-xs text-null-muted">
              {triggerEvents.length} events
            </span>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          <AnimatePresence>
            {triggerEvents.map(event => {
              const config = TOKEN_TYPES[event.type as keyof typeof TOKEN_TYPES]
              const Icon = config?.icon || AlertTriangle
              const isExpanded = expandedEvents.includes(event.id)

              return (
                <motion.div
                  key={event.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  className={`rounded-lg border ${
                    event.severity === 'critical'
                      ? 'bg-red-500/10 border-red-500/30'
                      : event.severity === 'high'
                      ? 'bg-orange-500/10 border-orange-500/30'
                      : 'bg-yellow-500/10 border-yellow-500/30'
                  }`}
                >
                  <button
                    onClick={() => setExpandedEvents(prev =>
                      isExpanded ? prev.filter(id => id !== event.id) : [...prev, event.id]
                    )}
                    className="w-full p-3 text-left"
                  >
                    <div className="flex items-start gap-3">
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-null-muted mt-0.5" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-null-muted mt-0.5" />
                      )}
                      <Icon className={`w-4 h-4 ${config?.color || 'text-red-400'} mt-0.5`} />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-null-text">
                            {event.honeytokenName}
                          </span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                            event.severity === 'critical'
                              ? 'bg-red-500/20 text-red-400'
                              : event.severity === 'high'
                              ? 'bg-orange-500/20 text-orange-400'
                              : 'bg-yellow-500/20 text-yellow-400'
                          }`}>
                            {event.severity.toUpperCase()}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-null-muted">
                          <span className="flex items-center gap-1">
                            <Globe className="w-3 h-3" />
                            {event.sourceIp}
                          </span>
                          {event.location && (
                            <span className="flex items-center gap-1">
                              <MapPin className="w-3 h-3" />
                              {event.location}
                            </span>
                          )}
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(event.timestamp).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </button>

                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden"
                      >
                        <div className="px-4 pb-3 pt-0 border-t border-null-border/50">
                          <div className="grid grid-cols-2 gap-4 mt-3">
                            {event.userAgent && (
                              <div>
                                <div className="text-[10px] text-null-muted uppercase">User Agent</div>
                                <div className="text-xs text-null-text font-mono">{event.userAgent}</div>
                              </div>
                            )}
                            <div>
                              <div className="text-[10px] text-null-muted uppercase">Source IP</div>
                              <div className="text-xs text-null-text font-mono">{event.sourceIp}</div>
                            </div>
                          </div>
                          {Object.keys(event.details).length > 0 && (
                            <div className="mt-3">
                              <div className="text-[10px] text-null-muted uppercase mb-1">Details</div>
                              <pre className="text-xs text-null-text font-mono bg-null-bg/50 p-2 rounded overflow-x-auto">
                                {JSON.stringify(event.details, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              )
            })}
          </AnimatePresence>

          {triggerEvents.length === 0 && (
            <div className="flex flex-col items-center justify-center h-64 text-null-muted">
              <Shield className="w-12 h-12 mb-4 opacity-50" />
              <p className="text-sm">No trigger events yet</p>
              <p className="text-xs mt-1">Deploy honeytokens to start detecting threats</p>
            </div>
          )}
        </div>
      </div>

      {/* Right Panel - Token Details */}
      <AnimatePresence>
        {selectedToken && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 400, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            className="border-l border-null-border flex flex-col overflow-hidden"
          >
            <div className="p-4 border-b border-null-border flex items-center justify-between">
              <span className="font-display text-null-text">Token Details</span>
              <button
                onClick={() => setSelectedToken(null)}
                className="text-null-muted hover:text-null-text"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4">
              {(() => {
                const config = TOKEN_TYPES[selectedToken.type]
                const Icon = config.icon

                return (
                  <>
                    <div className="flex items-center gap-3 mb-4">
                      <div className={`p-2 rounded-lg ${config.bg}`}>
                        <Icon className={`w-6 h-6 ${config.color}`} />
                      </div>
                      <div>
                        <h3 className="text-lg font-medium text-null-text">{selectedToken.name}</h3>
                        <p className="text-xs text-null-muted">{config.description}</p>
                      </div>
                    </div>

                    <div className="space-y-4">
                      {/* Status */}
                      <div className="flex items-center justify-between p-3 rounded-lg bg-null-surface/50">
                        <span className="text-sm text-null-muted">Status</span>
                        <button
                          onClick={() => toggleDeploy(selectedToken.id)}
                          className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                            selectedToken.deployed
                              ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                              : 'bg-null-border text-null-muted hover:bg-null-border/80'
                          }`}
                        >
                          {selectedToken.deployed ? 'Deployed' : 'Deploy'}
                        </button>
                      </div>

                      {/* Value */}
                      <div>
                        <div className="text-xs text-null-muted mb-2">Token Value</div>
                        <div className="relative">
                          <pre className="p-3 rounded-lg bg-null-bg border border-null-border text-xs text-null-text font-mono overflow-x-auto">
                            {selectedToken.value}
                          </pre>
                          <button
                            onClick={() => copyValue(selectedToken.id, selectedToken.value)}
                            className="absolute top-2 right-2 p-1.5 rounded bg-null-surface hover:bg-null-border"
                          >
                            {copiedId === selectedToken.id ? (
                              <CheckCircle className="w-3 h-3 text-green-400" />
                            ) : (
                              <Copy className="w-3 h-3 text-null-muted" />
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Location */}
                      <div>
                        <div className="text-xs text-null-muted mb-2">Deployment Location</div>
                        <div className="p-3 rounded-lg bg-null-surface/50 text-sm text-null-text">
                          {selectedToken.location}
                        </div>
                      </div>

                      {/* Stats */}
                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-3 rounded-lg bg-null-surface/50 text-center">
                          <div className="text-2xl font-mono text-red-400">{selectedToken.triggers}</div>
                          <div className="text-xs text-null-muted">Triggers</div>
                        </div>
                        <div className="p-3 rounded-lg bg-null-surface/50 text-center">
                          <div className="text-xs text-null-text">
                            {selectedToken.lastTriggered
                              ? new Date(selectedToken.lastTriggered).toLocaleDateString()
                              : 'Never'}
                          </div>
                          <div className="text-xs text-null-muted">Last Trigger</div>
                        </div>
                      </div>

                      {/* Notes */}
                      {selectedToken.notes && (
                        <div>
                          <div className="text-xs text-null-muted mb-2">Notes</div>
                          <div className="p-3 rounded-lg bg-null-surface/50 text-sm text-null-text">
                            {selectedToken.notes}
                          </div>
                        </div>
                      )}

                      {/* Created */}
                      <div className="text-xs text-null-muted flex items-center gap-2">
                        <Clock className="w-3 h-3" />
                        Created {new Date(selectedToken.created).toLocaleDateString()}
                      </div>

                      {/* Actions */}
                      <div className="flex gap-2 pt-4 border-t border-null-border">
                        <button
                          onClick={() => copyValue(selectedToken.id, selectedToken.value)}
                          className="flex-1 px-3 py-2 rounded bg-null-surface text-null-text text-xs hover:bg-null-border flex items-center justify-center gap-2"
                        >
                          <Copy className="w-3 h-3" />
                          Copy Value
                        </button>
                        <button
                          onClick={() => deleteToken(selectedToken.id)}
                          className="px-3 py-2 rounded bg-red-500/20 text-red-400 text-xs hover:bg-red-500/30"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  </>
                )
              })()}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Create Modal */}
      <AnimatePresence>
        {showCreateModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 flex items-center justify-center z-50"
            onClick={() => setShowCreateModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="w-[500px] bg-null-surface rounded-lg border border-null-border p-6"
              onClick={e => e.stopPropagation()}
            >
              <h3 className="text-lg font-display text-null-text mb-4">Create Honeytoken</h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs text-null-muted mb-1">Name</label>
                  <input
                    type="text"
                    value={newToken.name}
                    onChange={e => setNewToken({ ...newToken, name: e.target.value })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text"
                    placeholder="Production API Key..."
                  />
                </div>

                <div>
                  <label className="block text-xs text-null-muted mb-2">Type</label>
                  <div className="grid grid-cols-4 gap-2">
                    {Object.entries(TOKEN_TYPES).map(([type, config]) => {
                      const Icon = config.icon
                      return (
                        <button
                          key={type}
                          onClick={() => setNewToken({ ...newToken, type: type as keyof typeof TOKEN_TYPES })}
                          className={`p-2 rounded-lg border transition-colors ${
                            newToken.type === type
                              ? `${config.bg} border-current ${config.color}`
                              : 'border-null-border hover:border-null-muted'
                          }`}
                        >
                          <Icon className={`w-5 h-5 mx-auto mb-1 ${
                            newToken.type === type ? config.color : 'text-null-muted'
                          }`} />
                          <div className="text-[10px] text-center text-null-muted capitalize">
                            {type.replace('_', ' ')}
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>

                <div>
                  <label className="block text-xs text-null-muted mb-1">Deployment Location</label>
                  <input
                    type="text"
                    value={newToken.location}
                    onChange={e => setNewToken({ ...newToken, location: e.target.value })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text"
                    placeholder="/var/secrets/ or 'GitHub Repo'..."
                  />
                </div>

                <div>
                  <label className="block text-xs text-null-muted mb-1">Notes (optional)</label>
                  <textarea
                    value={newToken.notes}
                    onChange={e => setNewToken({ ...newToken, notes: e.target.value })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text h-20"
                    placeholder="Additional context..."
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-6">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded text-null-muted hover:text-null-text"
                >
                  Cancel
                </button>
                <button
                  onClick={createHoneytoken}
                  disabled={!newToken.name || !newToken.location}
                  className="px-4 py-2 rounded bg-green-500/20 text-green-400 hover:bg-green-500/30 disabled:opacity-50"
                >
                  Create Token
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
