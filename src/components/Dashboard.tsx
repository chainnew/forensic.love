import { motion } from 'framer-motion'
import {
  Skull, Shield, AlertTriangle, Bug, Target, Network,
  Clock, FileSearch, Activity, TrendingUp, Globe, Lock
} from 'lucide-react'

const THREAT_STATS = [
  { label: 'Critical Threats', value: 3, icon: Skull, color: 'text-null-danger', bg: 'bg-null-danger/10' },
  { label: 'Active Alerts', value: 47, icon: AlertTriangle, color: 'text-null-warning', bg: 'bg-null-warning/10' },
  { label: 'IOCs Tracked', value: 2847, icon: Bug, color: 'text-null-accent', bg: 'bg-null-accent/10' },
  { label: 'Protected Assets', value: 156, icon: Shield, color: 'text-null-primary', bg: 'bg-null-primary/10' },
]

const RECENT_EVENTS = [
  { time: '2m ago', type: 'critical', message: 'Suspicious PowerShell execution detected on DC-01', tactic: 'T1059.001' },
  { time: '5m ago', type: 'high', message: 'New lateral movement attempt from 10.0.0.45', tactic: 'T1021.001' },
  { time: '12m ago', type: 'medium', message: 'Anomalous DNS query to known C2 domain', tactic: 'T1071.004' },
  { time: '18m ago', type: 'low', message: 'Failed authentication attempts from external IP', tactic: 'T1110' },
  { time: '25m ago', type: 'info', message: 'New device connected to network segment VLAN-10', tactic: '-' },
]

const MITRE_COVERAGE = [
  { tactic: 'Initial Access', coverage: 78, techniques: 12 },
  { tactic: 'Execution', coverage: 85, techniques: 18 },
  { tactic: 'Persistence', coverage: 62, techniques: 8 },
  { tactic: 'Privilege Escalation', coverage: 71, techniques: 15 },
  { tactic: 'Defense Evasion', coverage: 45, techniques: 22 },
  { tactic: 'Credential Access', coverage: 89, techniques: 10 },
]

export default function Dashboard() {
  return (
    <div className="h-full overflow-auto p-6 grid-bg">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header stats */}
        <div className="grid grid-cols-4 gap-4">
          {THREAT_STATS.map((stat, i) => {
            const Icon = stat.icon
            return (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className={`${stat.bg} border border-null-border rounded-lg p-4 cyber-border`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-null-muted uppercase tracking-wider">{stat.label}</p>
                    <p className={`text-3xl font-display font-bold ${stat.color} mt-1`}>{stat.value}</p>
                  </div>
                  <Icon className={`w-8 h-8 ${stat.color} opacity-50`} />
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* Main content grid */}
        <div className="grid grid-cols-3 gap-6">
          {/* Recent events */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="col-span-2 bg-null-surface/50 border border-null-border rounded-lg"
          >
            <div className="p-4 border-b border-null-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-null-primary" />
                <span className="font-display text-sm">Live Threat Feed</span>
              </div>
              <span className="text-xs text-null-muted">Auto-refresh: 30s</span>
            </div>
            <div className="p-4 space-y-3">
              {RECENT_EVENTS.map((event, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="flex items-start gap-3 p-3 rounded bg-null-bg/50 border border-null-border/50"
                >
                  <div className={`
                    w-2 h-2 rounded-full mt-1.5
                    ${event.type === 'critical' ? 'bg-null-danger animate-pulse' :
                      event.type === 'high' ? 'bg-orange-500' :
                      event.type === 'medium' ? 'bg-null-warning' :
                      event.type === 'low' ? 'bg-null-info' : 'bg-null-muted'}
                  `} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-null-text">{event.message}</p>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-xs text-null-muted">{event.time}</span>
                      {event.tactic !== '-' && (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-mono">
                          {event.tactic}
                        </span>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* MITRE Coverage */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="bg-null-surface/50 border border-null-border rounded-lg"
          >
            <div className="p-4 border-b border-null-border flex items-center gap-2">
              <Target className="w-4 h-4 text-red-400" />
              <span className="font-display text-sm">ATT&CK Coverage</span>
            </div>
            <div className="p-4 space-y-3">
              {MITRE_COVERAGE.map((item, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-null-muted">{item.tactic}</span>
                    <span className="text-null-text">{item.coverage}%</span>
                  </div>
                  <div className="h-1.5 bg-null-border rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${item.coverage}%` }}
                      transition={{ delay: i * 0.1, duration: 0.5 }}
                      className={`h-full rounded-full ${
                        item.coverage > 80 ? 'bg-null-success' :
                        item.coverage > 60 ? 'bg-null-warning' : 'bg-null-danger'
                      }`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* Bottom panels */}
        <div className="grid grid-cols-3 gap-6">
          {/* Quick actions */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-null-surface/50 border border-null-border rounded-lg p-4"
          >
            <h3 className="font-display text-sm mb-4 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-null-primary" />
              Quick Actions
            </h3>
            <div className="space-y-2">
              {[
                { label: 'Start New Hunt', icon: Target },
                { label: 'Import IOCs', icon: Bug },
                { label: 'Run Scan', icon: Globe },
                { label: 'Generate Report', icon: FileSearch },
              ].map((action) => (
                <button
                  key={action.label}
                  className="w-full flex items-center gap-3 p-2.5 rounded bg-null-border/30 hover:bg-null-primary/10 hover:border-null-primary/30 border border-transparent transition-all text-left"
                >
                  <action.icon className="w-4 h-4 text-null-muted" />
                  <span className="text-sm text-null-text">{action.label}</span>
                </button>
              ))}
            </div>
          </motion.div>

          {/* Active investigations */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-null-surface/50 border border-null-border rounded-lg p-4"
          >
            <h3 className="font-display text-sm mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-null-warning" />
              Active Investigations
            </h3>
            <div className="space-y-3">
              {[
                { name: 'Ransomware Incident', status: 'in-progress', priority: 'critical' },
                { name: 'Data Exfiltration', status: 'in-progress', priority: 'high' },
                { name: 'Phishing Campaign', status: 'pending', priority: 'medium' },
              ].map((inv, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-null-bg/50">
                  <div>
                    <p className="text-sm text-null-text">{inv.name}</p>
                    <span className={`text-xs ${
                      inv.priority === 'critical' ? 'text-null-danger' :
                      inv.priority === 'high' ? 'text-orange-400' : 'text-null-warning'
                    }`}>{inv.priority}</span>
                  </div>
                  <div className={`w-2 h-2 rounded-full ${
                    inv.status === 'in-progress' ? 'bg-null-info animate-pulse' : 'bg-null-muted'
                  }`} />
                </div>
              ))}
            </div>
          </motion.div>

          {/* Threat Intel feeds */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-null-surface/50 border border-null-border rounded-lg p-4"
          >
            <h3 className="font-display text-sm mb-4 flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Threat Intel Feeds
            </h3>
            <div className="space-y-2">
              {[
                { name: 'AlienVault OTX', status: 'active', iocs: 1247 },
                { name: 'URLhaus', status: 'active', iocs: 892 },
                { name: 'MalwareBazaar', status: 'active', iocs: 456 },
                { name: 'CISA KEV', status: 'syncing', iocs: 156 },
              ].map((feed, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-null-bg/50">
                  <div className="flex items-center gap-2">
                    <div className={`w-1.5 h-1.5 rounded-full ${
                      feed.status === 'active' ? 'bg-null-success' : 'bg-null-warning animate-pulse'
                    }`} />
                    <span className="text-sm text-null-text">{feed.name}</span>
                  </div>
                  <span className="text-xs text-null-muted">{feed.iocs} IOCs</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  )
}
