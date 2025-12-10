import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Network, Shield, Clock, FileSearch, Brain, Target, Terminal,
  Settings, ChevronLeft, ChevronRight, Skull, Bug, AlertTriangle,
  Database, Globe, Lock, Search, Zap, Flame
} from 'lucide-react'
import Dashboard from './components/Dashboard'
import KnowledgeGraph from './components/KnowledgeGraph'
import MitreAttack from './components/MitreAttack'
import ForensicTimeline from './components/ForensicTimeline'
import LogViewer from './components/LogViewer'
import AgentPanel from './components/AgentPanel'
import AttackSurface from './components/AttackSurface'
import Sandbox from './components/Sandbox'
import Mincher from './components/Mincher'
import MacForensics from './components/MacForensics'
import YaraScanner from './components/YaraScanner'
import SigmaParser from './components/SigmaParser'
import ReportGatherer from './components/ReportGatherer'
import NexusGraph from './components/NexusGraph'
import CerebroAgent from './components/CerebroAgent'
import HivemindCollab from './components/HivemindCollab'
import MnemosyneRAG from './components/MnemosyneRAG'
import MimicHoneytokens from './components/MimicHoneytokens'
import CyberChefLite from './components/CyberChefLite'

type View = 'dashboard' | 'graph' | 'mitre' | 'timeline' | 'logs' | 'agents' | 'attack' | 'sandbox' | 'mincher' | 'macforensics' | 'yara' | 'sigma' | 'report' | 'nexus' | 'cerebro' | 'hivemind' | 'mnemosyne' | 'mimic' | 'cyberchef'

const NAV_ITEMS = [
  { id: 'dashboard' as const, icon: Zap, label: 'Dashboard', color: 'text-null-primary' },
  { id: 'agents' as const, icon: Brain, label: 'AI Agents', color: 'text-purple-400' },
  { id: 'graph' as const, icon: Network, label: 'Knowledge Graph', color: 'text-cyan-400' },
  { id: 'mitre' as const, icon: Target, label: 'MITRE ATT&CK', color: 'text-red-400' },
  { id: 'timeline' as const, icon: Clock, label: 'Timeline', color: 'text-yellow-400' },
  { id: 'logs' as const, icon: FileSearch, label: 'Log Viewer', color: 'text-green-400' },
  { id: 'attack' as const, icon: Globe, label: 'Attack Surface', color: 'text-orange-400' },
  { id: 'sandbox' as const, icon: Terminal, label: 'Sandbox', color: 'text-blue-400' },
  { id: 'mincher' as const, icon: Flame, label: 'Mincher', color: 'text-red-500' },
  { id: 'macforensics' as const, icon: Shield, label: 'Mac Forensics', color: 'text-gray-300' },
  { id: 'yara' as const, icon: Bug, label: 'YARA Scanner', color: 'text-yellow-500' },
  { id: 'sigma' as const, icon: FileSearch, label: 'Sigma Rules', color: 'text-indigo-400' },
  { id: 'report' as const, icon: FileSearch, label: 'Report Builder', color: 'text-purple-400' },
  { id: 'nexus' as const, icon: Network, label: 'NEXUS 3D', color: 'text-cyan-400' },
  { id: 'cerebro' as const, icon: Brain, label: 'CEREBRO AI', color: 'text-pink-400' },
  { id: 'hivemind' as const, icon: Globe, label: 'HIVEMIND', color: 'text-green-400' },
  { id: 'mnemosyne' as const, icon: Database, label: 'MNEMOSYNE', color: 'text-purple-400' },
  { id: 'mimic' as const, icon: Shield, label: 'MIMIC', color: 'text-green-500' },
  { id: 'cyberchef' as const, icon: Zap, label: 'CyberChef', color: 'text-yellow-400' },
]

function App() {
  const [activeView, setActiveView] = useState<View>('dashboard')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  const renderView = () => {
    switch (activeView) {
      case 'dashboard': return <Dashboard />
      case 'graph': return <KnowledgeGraph />
      case 'mitre': return <MitreAttack />
      case 'timeline': return <ForensicTimeline />
      case 'logs': return <LogViewer />
      case 'agents': return <AgentPanel />
      case 'attack': return <AttackSurface />
      case 'sandbox': return <Sandbox />
      case 'mincher': return <Mincher />
      case 'macforensics': return <MacForensics />
      case 'yara': return <YaraScanner />
      case 'sigma': return <SigmaParser />
      case 'report': return <ReportGatherer />
      case 'nexus': return <NexusGraph />
      case 'cerebro': return <CerebroAgent />
      case 'hivemind': return <HivemindCollab />
      case 'mnemosyne': return <MnemosyneRAG />
      case 'mimic': return <MimicHoneytokens />
      case 'cyberchef': return <CyberChefLite />
      default: return <Dashboard />
    }
  }

  return (
    <div className="h-screen w-screen flex bg-null-bg overflow-hidden">
      {/* Sidebar */}
      <motion.aside
        className="h-full bg-null-surface border-r border-null-border flex flex-col"
        animate={{ width: sidebarCollapsed ? 60 : 200 }}
        transition={{ duration: 0.2 }}
      >
        {/* Logo */}
        <div className="p-4 border-b border-null-border flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-gradient-to-br from-null-primary to-null-accent flex items-center justify-center">
            <Skull className="w-5 h-5 text-null-bg" />
          </div>
          <AnimatePresence>
            {!sidebarCollapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                className="font-display font-bold text-null-primary glow-text"
              >
                NULL
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-2 space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon
            const isActive = activeView === item.id
            return (
              <button
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`
                  w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all
                  ${isActive
                    ? 'bg-null-primary/10 border border-null-primary/30'
                    : 'hover:bg-null-border/50 border border-transparent'}
                `}
              >
                <Icon className={`w-5 h-5 ${isActive ? item.color : 'text-null-muted'}`} />
                <AnimatePresence>
                  {!sidebarCollapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className={`text-sm ${isActive ? 'text-null-text' : 'text-null-muted'}`}
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </button>
            )
          })}
        </nav>

        {/* Collapse toggle */}
        <div className="p-2 border-t border-null-border">
          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="w-full flex items-center justify-center p-2 rounded hover:bg-null-border/50 text-null-muted"
          >
            {sidebarCollapsed ? <ChevronRight className="w-5 h-5" /> : <ChevronLeft className="w-5 h-5" />}
          </button>
        </div>
      </motion.aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="h-12 border-b border-null-border bg-null-surface/50 flex items-center justify-between px-4">
          <div className="flex items-center gap-4">
            <h1 className="font-display text-sm text-null-text">
              {NAV_ITEMS.find(n => n.id === activeView)?.label}
            </h1>
            <div className="flex items-center gap-2 text-xs">
              <span className="px-2 py-0.5 rounded bg-null-danger/20 text-null-danger">
                <Bug className="w-3 h-3 inline mr-1" />
                3 Critical
              </span>
              <span className="px-2 py-0.5 rounded bg-null-warning/20 text-null-warning">
                <AlertTriangle className="w-3 h-3 inline mr-1" />
                12 Alerts
              </span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-null-border/50">
              <Search className="w-4 h-4 text-null-muted" />
              <input
                type="text"
                placeholder="Search (Cmd+K)"
                className="bg-transparent text-sm text-null-text placeholder:text-null-muted outline-none w-48"
              />
            </div>
            <button className="p-2 rounded hover:bg-null-border/50 text-null-muted">
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* Content area */}
        <div className="flex-1 overflow-hidden">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeView}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.15 }}
              className="h-full"
            >
              {renderView()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  )
}

export default App
