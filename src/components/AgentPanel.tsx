import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Brain, Search, Shield, Code, Send, Loader2, User,
  Maximize2, Minimize2, AlertTriangle, Target, FileCode, Zap
} from 'lucide-react'
import { sendAgentChat, DEMO_MODE } from '../services/api'

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
}

interface Agent {
  id: string
  name: string
  icon: typeof Brain
  color: string
  bgColor: string
  systemPrompt: string
  placeholder: string
  description: string
}

const AGENTS: Agent[] = [
  {
    id: 'analyst',
    name: 'ANALYST',
    icon: Search,
    color: 'text-cyan-400',
    bgColor: 'from-cyan-500/20 to-blue-600/20',
    systemPrompt: `You are ANALYST, an expert cybersecurity analyst AI agent specializing in:
- Log analysis and correlation
- Alert triage and severity scoring
- IOC extraction from unstructured data
- Threat pattern recognition
- Actionable security recommendations

Always provide structured analysis with clear severity ratings and recommended next steps.`,
    placeholder: 'Analyze this log entry, triage this alert...',
    description: 'Log analysis, alert triage, IOC extraction'
  },
  {
    id: 'hunter',
    name: 'HUNTER',
    icon: Target,
    color: 'text-red-400',
    bgColor: 'from-red-500/20 to-orange-600/20',
    systemPrompt: `You are HUNTER, an expert threat hunting AI agent specializing in:
- Hypothesis-driven threat hunting
- MITRE ATT&CK technique mapping
- Sigma/YARA rule generation
- APT TTP identification
- Proactive threat detection

Always map findings to MITRE ATT&CK techniques and provide detection rules when possible.`,
    placeholder: 'Hunt for lateral movement, map this behavior to MITRE...',
    description: 'Threat hunting, MITRE mapping, detection rules'
  },
  {
    id: 'forensic',
    name: 'FORENSIC',
    icon: Shield,
    color: 'text-green-400',
    bgColor: 'from-green-500/20 to-emerald-600/20',
    systemPrompt: `You are FORENSIC, an expert digital forensics AI agent specializing in:
- Evidence analysis and chain of custody
- Timeline reconstruction
- Memory and disk artifact analysis
- Network forensics
- Court-admissible documentation

Always maintain forensic rigor and document chain of custody considerations.`,
    placeholder: 'Analyze this memory dump, reconstruct the timeline...',
    description: 'Evidence analysis, timeline reconstruction'
  },
  {
    id: 'coder',
    name: 'CODER',
    icon: Code,
    color: 'text-purple-400',
    bgColor: 'from-purple-500/20 to-pink-600/20',
    systemPrompt: `You are CODER, an expert security code analysis AI agent specializing in:
- Vulnerability detection (OWASP, CWE)
- Malware pattern identification
- Code deobfuscation
- Secret scanning
- Secure code review

Always reference specific CWE/OWASP categories and provide remediation guidance.`,
    placeholder: 'Analyze this code for vulnerabilities, deobfuscate this script...',
    description: 'Vulnerability detection, code analysis'
  }
]

function AgentChat({ agent, isExpanded, onToggleExpand }: {
  agent: Agent
  isExpanded: boolean
  onToggleExpand: () => void
}) {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const Icon = agent.icon

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = async () => {
    if (!input.trim() || loading) return

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date()
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setLoading(true)

    try {
      const history = messages.map(m => ({
        role: m.role,
        content: m.content
      }))

      const data = await sendAgentChat(
        agent.id,
        userMessage.content,
        history.map(m => `${m.role}: ${m.content}`).join('\n')
      )

      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: data.response,
        timestamp: new Date()
      }])
    } catch (e) {
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: DEMO_MODE
          ? 'Demo mode: Simulated responses are enabled. Connect a backend for live AI.'
          : 'Connection error. Ensure the server is running on port 3081.',
        timestamp: new Date()
      }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <motion.div
      layout
      className={`
        bg-null-surface/50 border border-null-border rounded-lg flex flex-col overflow-hidden
        ${isExpanded ? 'col-span-2 row-span-2' : ''}
      `}
    >
      {/* Header */}
      <div className={`p-3 border-b border-null-border bg-gradient-to-r ${agent.bgColor} flex items-center justify-between`}>
        <div className="flex items-center gap-2">
          <Icon className={`w-5 h-5 ${agent.color}`} />
          <span className="font-display text-sm font-bold">{agent.name}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-null-muted">{agent.description}</span>
          <button
            onClick={onToggleExpand}
            className="p-1 hover:bg-null-border/50 rounded"
          >
            {isExpanded ? (
              <Minimize2 className="w-4 h-4 text-null-muted" />
            ) : (
              <Maximize2 className="w-4 h-4 text-null-muted" />
            )}
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3 min-h-[200px]">
        {messages.length === 0 && (
          <div className="text-center text-null-muted text-sm py-8">
            <Icon className={`w-8 h-8 mx-auto mb-2 opacity-30 ${agent.color}`} />
            <p>Start a conversation with {agent.name}</p>
          </div>
        )}
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : ''}`}
          >
            {msg.role === 'assistant' && (
              <Icon className={`w-5 h-5 ${agent.color} flex-shrink-0 mt-1`} />
            )}
            <div className={`
              max-w-[80%] rounded-lg p-2.5 text-sm
              ${msg.role === 'user'
                ? 'bg-null-primary/20 text-null-text'
                : 'bg-null-bg/50 text-null-text border border-null-border/50'}
            `}>
              <p className="whitespace-pre-wrap">{msg.content}</p>
            </div>
            {msg.role === 'user' && (
              <User className="w-5 h-5 text-null-muted flex-shrink-0 mt-1" />
            )}
          </div>
        ))}
        {loading && (
          <div className="flex gap-2">
            <Icon className={`w-5 h-5 ${agent.color} animate-pulse`} />
            <div className="flex gap-1.5 items-center py-2">
              <div className="w-2 h-2 rounded-full bg-null-primary animate-bounce" style={{ animationDelay: '0ms' }} />
              <div className="w-2 h-2 rounded-full bg-null-primary animate-bounce" style={{ animationDelay: '150ms' }} />
              <div className="w-2 h-2 rounded-full bg-null-primary animate-bounce" style={{ animationDelay: '300ms' }} />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-2 border-t border-null-border">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleSend()}
            placeholder={agent.placeholder}
            className="flex-1 bg-null-bg/50 border border-null-border rounded px-3 py-2 text-sm text-null-text placeholder:text-null-muted outline-none focus:border-null-primary/50"
            disabled={loading}
          />
          <button
            onClick={handleSend}
            disabled={loading || !input.trim()}
            className={`
              px-3 py-2 rounded border transition-all
              ${loading || !input.trim()
                ? 'bg-null-border/30 border-null-border text-null-muted'
                : `bg-gradient-to-r ${agent.bgColor} border-null-primary/30 ${agent.color}`}
            `}
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
          </button>
        </div>
      </div>
    </motion.div>
  )
}

export default function AgentPanel() {
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null)

  return (
    <div className="h-full overflow-auto p-4 grid-bg">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Brain className="w-6 h-6 text-null-primary" />
          <div>
            <h2 className="font-display text-lg">AI Security Agents</h2>
            <p className="text-xs text-null-muted">4x Grok 4.1 Fast - Specialized Security Analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-null-success/20 text-null-success">
            <Zap className="w-3 h-3" />
            <span>All agents online</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 h-[calc(100%-60px)]">
        {AGENTS.map((agent) => (
          <AgentChat
            key={agent.id}
            agent={agent}
            isExpanded={expandedAgent === agent.id}
            onToggleExpand={() => setExpandedAgent(
              expandedAgent === agent.id ? null : agent.id
            )}
          />
        ))}
      </div>
    </div>
  )
}
