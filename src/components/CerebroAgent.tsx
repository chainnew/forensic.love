import { useState, useRef, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Brain, Zap, Target, Network, Search, Shield, AlertTriangle,
  Play, Pause, RotateCcw, ChevronRight, ChevronDown, Clock,
  FileSearch, Database, Globe, Terminal, Activity, CheckCircle,
  XCircle, Loader2, MessageSquare, Sparkles, GitBranch, ArrowRight
} from 'lucide-react'

// Agent States based on LangGraph-style workflow
type AgentState = 'idle' | 'analyzing' | 'planning' | 'executing' | 'reporting' | 'complete' | 'error'

// Investigation Task Types
interface InvestigationTask {
  id: string
  type: 'enrich_ioc' | 'hunt_threat' | 'analyze_malware' | 'correlate_events' | 'generate_report'
  status: 'pending' | 'running' | 'complete' | 'failed'
  input: Record<string, unknown>
  output?: Record<string, unknown>
  startTime?: number
  endTime?: number
  error?: string
}

// Agent Thought/Action for transparency
interface AgentThought {
  id: string
  timestamp: number
  type: 'thought' | 'action' | 'observation' | 'tool_call' | 'decision'
  content: string
  metadata?: Record<string, unknown>
}

// Investigation Session
interface Investigation {
  id: string
  query: string
  state: AgentState
  tasks: InvestigationTask[]
  thoughts: AgentThought[]
  findings: Finding[]
  startTime: number
  endTime?: number
}

interface Finding {
  id: string
  type: 'ioc' | 'technique' | 'actor' | 'vulnerability' | 'recommendation'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  confidence: number
  evidence: string[]
  mitreTechnique?: string
}

// Available Tools for the Agent
const AGENT_TOOLS = [
  { id: 'vt_lookup', name: 'VirusTotal Lookup', icon: Shield, description: 'Check IOCs against VirusTotal' },
  { id: 'mitre_map', name: 'MITRE Mapper', icon: Target, description: 'Map behaviors to ATT&CK techniques' },
  { id: 'yara_scan', name: 'YARA Scanner', icon: FileSearch, description: 'Scan samples with YARA rules' },
  { id: 'sigma_detect', name: 'Sigma Detection', icon: AlertTriangle, description: 'Apply Sigma detection rules' },
  { id: 'osint_search', name: 'OSINT Search', icon: Globe, description: 'Search threat intelligence feeds' },
  { id: 'graph_analysis', name: 'Graph Analysis', icon: Network, description: 'Analyze entity relationships' },
  { id: 'memory_search', name: 'Memory Search', icon: Database, description: 'Search vector memory for context' },
]

// Simulated investigation workflow
const DEMO_INVESTIGATION: Investigation = {
  id: 'inv-001',
  query: 'Investigate potential APT29 activity related to the compromised domain solarwinds.com',
  state: 'complete',
  startTime: Date.now() - 120000,
  endTime: Date.now() - 5000,
  tasks: [
    { id: 't1', type: 'enrich_ioc', status: 'complete', input: { ioc: 'solarwinds.com', type: 'domain' }, output: { malicious: true, vtScore: 45 } },
    { id: 't2', type: 'hunt_threat', status: 'complete', input: { actor: 'APT29' }, output: { matches: 12 } },
    { id: 't3', type: 'correlate_events', status: 'complete', input: { timeRange: '30d' }, output: { correlations: 8 } },
    { id: 't4', type: 'generate_report', status: 'complete', input: {}, output: { reportId: 'rpt-001' } },
  ],
  thoughts: [
    { id: 'th1', timestamp: Date.now() - 115000, type: 'thought', content: 'User is asking about APT29 activity. I should first enrich the provided domain IOC.' },
    { id: 'th2', timestamp: Date.now() - 110000, type: 'action', content: 'Calling VirusTotal API for domain solarwinds.com' },
    { id: 'th3', timestamp: Date.now() - 100000, type: 'observation', content: 'VT returned 45/93 detections. Domain is flagged as malicious. Associated with SUNBURST malware.' },
    { id: 'th4', timestamp: Date.now() - 95000, type: 'thought', content: 'High confidence of malicious activity. Should search for related APT29 TTPs in our threat intelligence.' },
    { id: 'th5', timestamp: Date.now() - 90000, type: 'tool_call', content: 'Searching MNEMOSYNE vector store for "APT29 SUNBURST supply chain"' },
    { id: 'th6', timestamp: Date.now() - 80000, type: 'observation', content: 'Found 12 related threat reports. Key techniques: T1195.002, T1059.001, T1027, T1021.002' },
    { id: 'th7', timestamp: Date.now() - 70000, type: 'decision', content: 'Evidence strongly suggests APT29 supply chain attack. Proceeding to correlate with internal logs.' },
    { id: 'th8', timestamp: Date.now() - 60000, type: 'action', content: 'Correlating indicators with internal event data from the past 30 days.' },
    { id: 'th9', timestamp: Date.now() - 40000, type: 'observation', content: 'Found 8 correlated events: 3 DNS queries, 2 HTTP connections, 3 process executions matching SUNBURST behavior.' },
    { id: 'th10', timestamp: Date.now() - 20000, type: 'thought', content: 'Investigation complete. High confidence APT29 activity detected. Generating comprehensive report.' },
  ],
  findings: [
    {
      id: 'f1',
      type: 'actor',
      severity: 'critical',
      title: 'APT29 (Cozy Bear) Activity Confirmed',
      description: 'Strong indicators of APT29 involvement through SolarWinds supply chain compromise.',
      confidence: 95,
      evidence: ['VT detection 45/93', '12 matching threat reports', '8 correlated internal events'],
      mitreTechnique: 'T1195.002',
    },
    {
      id: 'f2',
      type: 'technique',
      severity: 'high',
      title: 'Supply Chain Compromise Detected',
      description: 'Evidence of compromised SolarWinds Orion software used as initial access vector.',
      confidence: 92,
      evidence: ['DNS queries to avsvmcloud.com', 'HTTP beacons to C2 infrastructure'],
      mitreTechnique: 'T1195.002',
    },
    {
      id: 'f3',
      type: 'ioc',
      severity: 'high',
      title: 'Malicious C2 Domain Identified',
      description: 'avsvmcloud.com confirmed as SUNBURST C2 infrastructure.',
      confidence: 98,
      evidence: ['VT flagged', 'OSINT correlation', 'Internal DNS logs'],
    },
    {
      id: 'f4',
      type: 'recommendation',
      severity: 'critical',
      title: 'Immediate Containment Required',
      description: 'Isolate affected systems, block C2 domains, preserve forensic evidence.',
      confidence: 100,
      evidence: ['Active threat indicators', 'Lateral movement potential'],
    },
  ],
}

export default function CerebroAgent() {
  const [query, setQuery] = useState('')
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [showThoughts, setShowThoughts] = useState(true)
  const [selectedTool, setSelectedTool] = useState<string | null>(null)
  const thoughtsEndRef = useRef<HTMLDivElement>(null)

  // Auto-scroll thoughts
  useEffect(() => {
    if (thoughtsEndRef.current) {
      thoughtsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [activeInvestigation?.thoughts.length])

  // Simulate investigation
  const startInvestigation = useCallback(() => {
    if (!query.trim()) return

    setIsRunning(true)
    const investigation: Investigation = {
      id: `inv-${Date.now()}`,
      query,
      state: 'analyzing',
      tasks: [],
      thoughts: [],
      findings: [],
      startTime: Date.now(),
    }
    setActiveInvestigation(investigation)

    // Simulate thought stream
    const thoughts = [
      { delay: 500, type: 'thought' as const, content: `Analyzing query: "${query}"` },
      { delay: 1500, type: 'action' as const, content: 'Parsing entities and IOCs from query...' },
      { delay: 2500, type: 'observation' as const, content: 'Identified potential threat actor reference and domain indicator.' },
      { delay: 3500, type: 'tool_call' as const, content: 'Calling VirusTotal enrichment API...' },
      { delay: 5000, type: 'observation' as const, content: 'Received threat intelligence data. Processing results...' },
      { delay: 6500, type: 'thought' as const, content: 'Evidence suggests sophisticated adversary. Expanding investigation scope.' },
      { delay: 8000, type: 'action' as const, content: 'Searching vector memory for related historical incidents...' },
      { delay: 10000, type: 'decision' as const, content: 'Investigation complete. Generating findings report.' },
    ]

    thoughts.forEach(({ delay, type, content }) => {
      setTimeout(() => {
        setActiveInvestigation(prev => {
          if (!prev) return null
          return {
            ...prev,
            thoughts: [...prev.thoughts, {
              id: `th-${Date.now()}`,
              timestamp: Date.now(),
              type,
              content,
            }],
          }
        })
      }, delay)
    })

    // Complete investigation after thoughts
    setTimeout(() => {
      setActiveInvestigation(prev => {
        if (!prev) return null
        return {
          ...prev,
          state: 'complete',
          endTime: Date.now(),
          findings: DEMO_INVESTIGATION.findings,
        }
      })
      setIsRunning(false)
    }, 12000)
  }, [query])

  // Load demo investigation
  const loadDemo = useCallback(() => {
    setActiveInvestigation(DEMO_INVESTIGATION)
    setQuery(DEMO_INVESTIGATION.query)
  }, [])

  // Reset
  const reset = useCallback(() => {
    setActiveInvestigation(null)
    setQuery('')
    setIsRunning(false)
  }, [])

  const getThoughtIcon = (type: AgentThought['type']) => {
    switch (type) {
      case 'thought': return <Brain className="w-3 h-3" />
      case 'action': return <Zap className="w-3 h-3" />
      case 'observation': return <Search className="w-3 h-3" />
      case 'tool_call': return <Terminal className="w-3 h-3" />
      case 'decision': return <CheckCircle className="w-3 h-3" />
    }
  }

  const getThoughtColor = (type: AgentThought['type']) => {
    switch (type) {
      case 'thought': return 'text-purple-400 bg-purple-500/10 border-purple-500/30'
      case 'action': return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30'
      case 'observation': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
      case 'tool_call': return 'text-blue-400 bg-blue-500/10 border-blue-500/30'
      case 'decision': return 'text-green-400 bg-green-500/10 border-green-500/30'
    }
  }

  return (
    <div className="h-full flex bg-null-bg">
      {/* Main Investigation Panel */}
      <div className="flex-1 flex flex-col">
        {/* Header with Query Input */}
        <div className="p-4 border-b border-null-border bg-null-surface">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-pink-400">
              <Brain className="w-6 h-6" />
              <span className="font-display font-bold">CEREBRO</span>
            </div>
            <div className="flex-1 relative">
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && startInvestigation()}
                placeholder="Describe the threat to investigate... (e.g., 'Investigate suspicious PowerShell activity from 192.168.1.50')"
                className="w-full px-4 py-2.5 bg-null-bg border border-null-border rounded-lg text-sm text-null-text placeholder:text-null-muted focus:outline-none focus:border-pink-500/50"
                disabled={isRunning}
              />
              <Sparkles className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-pink-400" />
            </div>
            <button
              onClick={startInvestigation}
              disabled={isRunning || !query.trim()}
              className={`px-4 py-2 rounded-lg flex items-center gap-2 transition-all ${
                isRunning
                  ? 'bg-null-border text-null-muted cursor-not-allowed'
                  : 'bg-pink-500/20 border border-pink-500/50 text-pink-400 hover:bg-pink-500/30'
              }`}
            >
              {isRunning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Investigating...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span className="text-sm">Investigate</span>
                </>
              )}
            </button>
            <button
              onClick={loadDemo}
              className="px-3 py-2 rounded-lg bg-null-surface border border-null-border text-null-muted hover:text-null-text transition-colors text-sm"
            >
              Load Demo
            </button>
            <button
              onClick={reset}
              className="p-2 rounded-lg bg-null-surface border border-null-border text-null-muted hover:text-null-text transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Investigation Content */}
        <div className="flex-1 flex overflow-hidden">
          {/* Agent Thoughts Stream */}
          <div className="w-96 border-r border-null-border flex flex-col bg-null-surface/50">
            <div className="p-3 border-b border-null-border flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-medium text-null-text">
                <Activity className="w-4 h-4 text-pink-400" />
                <span>Agent Reasoning</span>
              </div>
              <button
                onClick={() => setShowThoughts(!showThoughts)}
                className="text-null-muted hover:text-null-text"
              >
                {showThoughts ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              </button>
            </div>

            <AnimatePresence>
              {showThoughts && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="flex-1 overflow-auto p-3 space-y-2"
                >
                  {!activeInvestigation ? (
                    <div className="text-center py-8 text-null-muted">
                      <Brain className="w-12 h-12 mx-auto mb-3 opacity-30" />
                      <p className="text-sm">Start an investigation to see agent reasoning</p>
                    </div>
                  ) : (
                    <>
                      {activeInvestigation.thoughts.map((thought, idx) => (
                        <motion.div
                          key={thought.id}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: idx * 0.05 }}
                          className={`p-2.5 rounded-lg border ${getThoughtColor(thought.type)}`}
                        >
                          <div className="flex items-start gap-2">
                            <div className="mt-0.5">
                              {getThoughtIcon(thought.type)}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="text-[10px] uppercase tracking-wider opacity-70 mb-1">
                                {thought.type}
                              </div>
                              <p className="text-xs leading-relaxed">{thought.content}</p>
                            </div>
                          </div>
                        </motion.div>
                      ))}
                      {isRunning && (
                        <div className="flex items-center gap-2 text-pink-400 text-xs">
                          <Loader2 className="w-3 h-3 animate-spin" />
                          <span>Processing...</span>
                        </div>
                      )}
                      <div ref={thoughtsEndRef} />
                    </>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Findings Panel */}
          <div className="flex-1 overflow-auto p-4">
            {!activeInvestigation ? (
              <div className="h-full flex items-center justify-center">
                <div className="text-center max-w-md">
                  <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-pink-500/10 border border-pink-500/30 flex items-center justify-center">
                    <Brain className="w-10 h-10 text-pink-400" />
                  </div>
                  <h2 className="text-lg font-medium text-null-text mb-2">CEREBRO Agentic AI</h2>
                  <p className="text-sm text-null-muted mb-4">
                    Autonomous threat investigation powered by multi-model AI reasoning.
                    Describe a threat scenario and CEREBRO will investigate, correlate, and report.
                  </p>
                  <div className="flex flex-wrap gap-2 justify-center">
                    {['APT29 activity', 'Ransomware indicators', 'Suspicious PowerShell', 'Data exfiltration'].map(example => (
                      <button
                        key={example}
                        onClick={() => setQuery(`Investigate ${example}`)}
                        className="px-3 py-1.5 rounded-full bg-null-surface border border-null-border text-xs text-null-muted hover:text-null-text hover:border-pink-500/30 transition-colors"
                      >
                        {example}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : activeInvestigation.state === 'complete' ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium text-null-text">Investigation Findings</h3>
                  <span className="text-xs text-null-muted">
                    Completed in {((activeInvestigation.endTime! - activeInvestigation.startTime) / 1000).toFixed(1)}s
                  </span>
                </div>

                <div className="space-y-3">
                  {activeInvestigation.findings.map((finding, idx) => (
                    <motion.div
                      key={finding.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="p-4 bg-null-surface rounded-lg border border-null-border"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${
                              finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                              finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                              finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              {finding.severity}
                            </span>
                            <span className="px-2 py-0.5 rounded bg-null-border text-[10px] text-null-muted uppercase">
                              {finding.type}
                            </span>
                            {finding.mitreTechnique && (
                              <span className="px-2 py-0.5 rounded bg-purple-500/20 text-[10px] text-purple-400 font-mono">
                                {finding.mitreTechnique}
                              </span>
                            )}
                          </div>
                          <h4 className="text-sm font-medium text-null-text mb-1">{finding.title}</h4>
                          <p className="text-xs text-null-muted mb-3">{finding.description}</p>
                          <div className="flex flex-wrap gap-1">
                            {finding.evidence.map((ev, i) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-null-bg text-[10px] text-null-muted">
                                {ev}
                              </span>
                            ))}
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-[10px] text-null-muted mb-1">Confidence</div>
                          <div className="text-lg font-mono text-pink-400">{finding.confidence}%</div>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="h-full flex items-center justify-center">
                <div className="text-center">
                  <Loader2 className="w-12 h-12 mx-auto mb-4 text-pink-400 animate-spin" />
                  <p className="text-sm text-null-muted">Investigation in progress...</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Right Panel - Tools & Context */}
      <div className="w-64 border-l border-null-border bg-null-surface flex flex-col">
        <div className="p-3 border-b border-null-border">
          <h4 className="text-xs font-medium text-null-muted uppercase tracking-wider">Available Tools</h4>
        </div>
        <div className="flex-1 overflow-auto p-2 space-y-1">
          {AGENT_TOOLS.map(tool => {
            const Icon = tool.icon
            return (
              <button
                key={tool.id}
                onClick={() => setSelectedTool(selectedTool === tool.id ? null : tool.id)}
                className={`w-full p-2 rounded-lg text-left transition-all ${
                  selectedTool === tool.id
                    ? 'bg-pink-500/10 border border-pink-500/30'
                    : 'bg-null-bg border border-transparent hover:border-null-border'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${selectedTool === tool.id ? 'text-pink-400' : 'text-null-muted'}`} />
                  <span className="text-xs text-null-text">{tool.name}</span>
                </div>
                {selectedTool === tool.id && (
                  <p className="mt-1.5 text-[10px] text-null-muted pl-6">{tool.description}</p>
                )}
              </button>
            )
          })}
        </div>

        {/* Investigation Stats */}
        {activeInvestigation && (
          <div className="p-3 border-t border-null-border space-y-2">
            <h4 className="text-xs font-medium text-null-muted uppercase tracking-wider">Stats</h4>
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 bg-null-bg rounded border border-null-border">
                <div className="text-[10px] text-null-muted">Thoughts</div>
                <div className="text-sm font-mono text-null-text">{activeInvestigation.thoughts.length}</div>
              </div>
              <div className="p-2 bg-null-bg rounded border border-null-border">
                <div className="text-[10px] text-null-muted">Findings</div>
                <div className="text-sm font-mono text-null-text">{activeInvestigation.findings.length}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
