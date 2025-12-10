import { useState, useRef, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Terminal, Play, Square, Trash2, Download, Upload,
  FileCode, Lock, Hash, Clock, AlertTriangle, CheckCircle2, Copy
} from 'lucide-react'

interface Artifact {
  id: string
  name: string
  type: 'code' | 'document' | 'binary' | 'log'
  content: string
  sha256: string
  encrypted: boolean
  createdAt: Date
}

interface ExecutionResult {
  id: string
  command: string
  output: string
  exitCode: number
  timestamp: Date
  duration: number
}

const SAMPLE_ARTIFACTS: Artifact[] = [
  {
    id: '1',
    name: 'malware_sample.ps1',
    type: 'code',
    content: '# PowerShell script - potentially malicious\n$encoded = "aQBlAHgA..."\nIEX([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))',
    sha256: 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890',
    encrypted: false,
    createdAt: new Date('2025-12-10T10:00:00')
  },
  {
    id: '2',
    name: 'investigation_report.md',
    type: 'document',
    content: '# Investigation Report\n\n## Summary\nMalware analysis of suspected ransomware...',
    sha256: 'b2c3d4e5f6789012345678901234567890123456789012345678901234567890ab',
    encrypted: true,
    createdAt: new Date('2025-12-10T09:00:00')
  },
]

export default function Sandbox() {
  const [artifacts, setArtifacts] = useState<Artifact[]>(SAMPLE_ARTIFACTS)
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null)
  const [executions, setExecutions] = useState<ExecutionResult[]>([])
  const [command, setCommand] = useState('')
  const [running, setRunning] = useState(false)
  const [newArtifactContent, setNewArtifactContent] = useState('')
  const [showNewArtifact, setShowNewArtifact] = useState(false)
  const terminalRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [executions])

  const executeCommand = async () => {
    if (!command.trim() || running) return

    setRunning(true)
    const startTime = Date.now()

    // Simulate sandbox execution
    await new Promise(r => setTimeout(r, 1000 + Math.random() * 2000))

    const result: ExecutionResult = {
      id: Date.now().toString(),
      command: command,
      output: `Executing in isolated sandbox...\n\n$ ${command}\n\n[OUTPUT]\nCommand executed successfully in sandboxed environment.\nNo network access allowed.\nFile system changes isolated.\n\n[ANALYSIS]\n- No malicious behavior detected\n- Memory usage: 45MB\n- CPU time: 0.12s`,
      exitCode: 0,
      timestamp: new Date(),
      duration: Date.now() - startTime
    }

    setExecutions(prev => [...prev, result])
    setCommand('')
    setRunning(false)
  }

  const handleFileDrop = async (e: React.DragEvent) => {
    e.preventDefault()
    const files = Array.from(e.dataTransfer.files)

    for (const file of files) {
      const content = await file.text()
      const buffer = await file.arrayBuffer()
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

      const artifact: Artifact = {
        id: Date.now().toString() + Math.random(),
        name: file.name,
        type: file.name.endsWith('.log') ? 'log' :
              file.name.match(/\.(js|ts|py|ps1|sh|rb|go)$/) ? 'code' :
              file.name.match(/\.(md|txt|doc)$/) ? 'document' : 'binary',
        content,
        sha256,
        encrypted: false,
        createdAt: new Date()
      }

      setArtifacts(prev => [artifact, ...prev])
    }
  }

  const createArtifact = () => {
    if (!newArtifactContent.trim()) return

    const artifact: Artifact = {
      id: Date.now().toString(),
      name: `artifact_${Date.now()}.txt`,
      type: 'document',
      content: newArtifactContent,
      sha256: 'pending...',
      encrypted: false,
      createdAt: new Date()
    }

    // Calculate SHA256
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(newArtifactContent))
      .then(buffer => {
        const hashArray = Array.from(new Uint8Array(buffer))
        artifact.sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
        setArtifacts(prev => prev.map(a => a.id === artifact.id ? artifact : a))
      })

    setArtifacts(prev => [artifact, ...prev])
    setNewArtifactContent('')
    setShowNewArtifact(false)
  }

  const toggleEncryption = (artifact: Artifact) => {
    setArtifacts(prev => prev.map(a =>
      a.id === artifact.id ? { ...a, encrypted: !a.encrypted } : a
    ))
  }

  return (
    <div className="h-full flex">
      {/* Left panel - Artifacts */}
      <div className="w-80 border-r border-null-border flex flex-col bg-null-surface/30">
        <div className="p-3 border-b border-null-border">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-display text-sm">Artifacts</h3>
            <button
              onClick={() => setShowNewArtifact(true)}
              className="p-1.5 rounded bg-null-primary/20 text-null-primary hover:bg-null-primary/30"
            >
              <FileCode className="w-4 h-4" />
            </button>
          </div>

          {/* Drop zone */}
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleFileDrop}
            onClick={() => fileInputRef.current?.click()}
            className="p-3 border-2 border-dashed border-null-border rounded-lg text-center cursor-pointer hover:border-null-primary/50 transition-all"
          >
            <Upload className="w-5 h-5 mx-auto text-null-muted mb-1" />
            <p className="text-xs text-null-muted">Drop files or click</p>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              onChange={(e) => {
                if (e.target.files) {
                  const dt = new DataTransfer()
                  Array.from(e.target.files).forEach(f => dt.items.add(f))
                  handleFileDrop({ preventDefault: () => {}, dataTransfer: dt } as any)
                }
              }}
              className="hidden"
            />
          </div>
        </div>

        {/* New artifact modal */}
        {showNewArtifact && (
          <div className="p-3 border-b border-null-border bg-null-bg/50">
            <textarea
              value={newArtifactContent}
              onChange={(e) => setNewArtifactContent(e.target.value)}
              placeholder="Paste content here..."
              className="w-full h-24 bg-null-bg/50 border border-null-border rounded p-2 text-sm text-null-text placeholder:text-null-muted outline-none resize-none font-mono"
            />
            <div className="flex gap-2 mt-2">
              <button
                onClick={createArtifact}
                className="flex-1 px-2 py-1.5 rounded bg-null-primary/20 text-null-primary text-xs"
              >
                Create
              </button>
              <button
                onClick={() => { setShowNewArtifact(false); setNewArtifactContent('') }}
                className="px-2 py-1.5 rounded bg-null-border text-null-muted text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Artifact list */}
        <div className="flex-1 overflow-y-auto p-2 space-y-2">
          {artifacts.map((artifact) => (
            <motion.div
              key={artifact.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`
                p-3 rounded-lg border cursor-pointer transition-all
                ${selectedArtifact?.id === artifact.id
                  ? 'bg-null-primary/10 border-null-primary/30'
                  : 'bg-null-bg/50 border-null-border hover:border-null-primary/30'}
              `}
              onClick={() => setSelectedArtifact(artifact)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode className={`w-4 h-4 ${
                    artifact.type === 'code' ? 'text-yellow-400' :
                    artifact.type === 'document' ? 'text-cyan-400' :
                    artifact.type === 'log' ? 'text-green-400' : 'text-purple-400'
                  }`} />
                  <span className="text-sm text-null-text truncate max-w-[150px]">{artifact.name}</span>
                </div>
                {artifact.encrypted && <Lock className="w-3 h-3 text-null-success" />}
              </div>

              <div className="flex items-center gap-1 mt-2 text-xs text-null-muted">
                <Hash className="w-3 h-3" />
                <span className="font-mono truncate">{artifact.sha256.slice(0, 16)}...</span>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col">
        {/* Terminal */}
        <div className="flex-1 flex flex-col bg-null-bg">
          <div className="p-2 border-b border-null-border bg-null-surface/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-null-primary" />
              <span className="text-sm font-mono">Sandbox Terminal</span>
              <span className="text-xs px-1.5 py-0.5 rounded bg-null-success/20 text-null-success">Isolated</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setExecutions([])}
                className="p-1.5 rounded hover:bg-null-border/50 text-null-muted"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Output */}
          <div ref={terminalRef} className="flex-1 overflow-y-auto p-4 font-mono text-sm">
            <div className="text-null-muted mb-4">
              <p>NULL SPAWN Sandbox v1.0.0</p>
              <p>Isolated execution environment - No network, No persistence</p>
              <p className="text-null-success">Ready for analysis.</p>
              <p className="mt-2">Type commands below or analyze uploaded artifacts.</p>
            </div>

            {executions.map((exec) => (
              <div key={exec.id} className="mb-4">
                <div className="flex items-center gap-2 text-null-primary">
                  <span>$</span>
                  <span>{exec.command}</span>
                </div>
                <pre className="mt-1 text-null-text whitespace-pre-wrap">{exec.output}</pre>
                <div className="flex items-center gap-3 mt-1 text-xs text-null-muted">
                  <span className={exec.exitCode === 0 ? 'text-null-success' : 'text-null-danger'}>
                    Exit: {exec.exitCode}
                  </span>
                  <span>{exec.duration}ms</span>
                </div>
              </div>
            ))}

            {running && (
              <div className="flex items-center gap-2 text-null-warning">
                <Clock className="w-4 h-4 animate-spin" />
                <span>Executing in sandbox...</span>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="p-2 border-t border-null-border bg-null-surface/30">
            <div className="flex gap-2">
              <span className="text-null-primary font-mono">$</span>
              <input
                type="text"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && executeCommand()}
                placeholder="Enter command..."
                className="flex-1 bg-transparent text-null-text placeholder:text-null-muted outline-none font-mono"
                disabled={running}
              />
              <button
                onClick={executeCommand}
                disabled={running || !command.trim()}
                className="px-3 py-1 rounded bg-null-primary/20 text-null-primary disabled:opacity-50"
              >
                <Play className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {/* Artifact viewer */}
        {selectedArtifact && (
          <div className="h-1/2 border-t border-null-border bg-null-surface/30 flex flex-col">
            <div className="p-2 border-b border-null-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-mono">{selectedArtifact.name}</span>
                {selectedArtifact.encrypted && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-null-success/20 text-null-success">Encrypted</span>
                )}
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => toggleEncryption(selectedArtifact)}
                  className="p-1.5 rounded hover:bg-null-border/50 text-null-muted"
                  title={selectedArtifact.encrypted ? 'Decrypt' : 'Encrypt'}
                >
                  {selectedArtifact.encrypted ? <Lock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => navigator.clipboard.writeText(selectedArtifact.content)}
                  className="p-1.5 rounded hover:bg-null-border/50 text-null-muted"
                >
                  <Copy className="w-4 h-4" />
                </button>
                <button className="p-1.5 rounded hover:bg-null-border/50 text-null-muted">
                  <Download className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-auto p-4">
              {selectedArtifact.encrypted ? (
                <div className="flex flex-col items-center justify-center h-full text-null-muted">
                  <Lock className="w-8 h-8 mb-2 opacity-50" />
                  <p className="text-sm">Content encrypted</p>
                  <button className="mt-2 px-3 py-1 rounded bg-null-primary/20 text-null-primary text-sm">
                    Decrypt to view
                  </button>
                </div>
              ) : (
                <pre className="font-mono text-sm text-null-text whitespace-pre-wrap">
                  {selectedArtifact.content}
                </pre>
              )}
            </div>

            {/* SHA256 */}
            <div className="p-2 border-t border-null-border bg-null-bg/50 flex items-center gap-2">
              <Hash className="w-4 h-4 text-null-muted" />
              <span className="text-xs text-null-muted font-mono">{selectedArtifact.sha256}</span>
              <button
                onClick={() => navigator.clipboard.writeText(selectedArtifact.sha256)}
                className="p-1 rounded hover:bg-null-border/50 text-null-muted"
              >
                <Copy className="w-3 h-3" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
