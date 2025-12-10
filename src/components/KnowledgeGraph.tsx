import { useState, useCallback, useMemo } from 'react'
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  BackgroundVariant
} from 'reactflow'
import 'reactflow/dist/style.css'
import { motion } from 'framer-motion'
import {
  Network, Plus, Search, Filter, Download, Upload,
  Bug, Shield, FileText, Globe, User, Server, AlertTriangle
} from 'lucide-react'

const nodeTypes = {
  ioc: ({ data }: { data: { label: string; type: string } }) => (
    <div className="px-3 py-2 rounded-lg bg-gradient-to-r from-red-900/50 to-red-700/50 border border-red-500/30 min-w-[120px]">
      <div className="flex items-center gap-2">
        <Bug className="w-4 h-4 text-red-400" />
        <span className="text-sm text-null-text">{data.label}</span>
      </div>
      <span className="text-xs text-red-400">{data.type}</span>
    </div>
  ),
  threat: ({ data }: { data: { label: string; severity: string } }) => (
    <div className="px-3 py-2 rounded-lg bg-gradient-to-r from-orange-900/50 to-orange-700/50 border border-orange-500/30 min-w-[120px]">
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-orange-400" />
        <span className="text-sm text-null-text">{data.label}</span>
      </div>
      <span className="text-xs text-orange-400">{data.severity}</span>
    </div>
  ),
  asset: ({ data }: { data: { label: string; type: string } }) => (
    <div className="px-3 py-2 rounded-lg bg-gradient-to-r from-cyan-900/50 to-cyan-700/50 border border-cyan-500/30 min-w-[120px]">
      <div className="flex items-center gap-2">
        <Server className="w-4 h-4 text-cyan-400" />
        <span className="text-sm text-null-text">{data.label}</span>
      </div>
      <span className="text-xs text-cyan-400">{data.type}</span>
    </div>
  ),
  actor: ({ data }: { data: { label: string; group: string } }) => (
    <div className="px-3 py-2 rounded-lg bg-gradient-to-r from-purple-900/50 to-purple-700/50 border border-purple-500/30 min-w-[120px]">
      <div className="flex items-center gap-2">
        <User className="w-4 h-4 text-purple-400" />
        <span className="text-sm text-null-text">{data.label}</span>
      </div>
      <span className="text-xs text-purple-400">{data.group}</span>
    </div>
  ),
  evidence: ({ data }: { data: { label: string; case: string } }) => (
    <div className="px-3 py-2 rounded-lg bg-gradient-to-r from-green-900/50 to-green-700/50 border border-green-500/30 min-w-[120px]">
      <div className="flex items-center gap-2">
        <FileText className="w-4 h-4 text-green-400" />
        <span className="text-sm text-null-text">{data.label}</span>
      </div>
      <span className="text-xs text-green-400">{data.case}</span>
    </div>
  ),
}

const initialNodes: Node[] = [
  { id: '1', type: 'threat', position: { x: 400, y: 100 }, data: { label: 'APT29 Campaign', severity: 'Critical' } },
  { id: '2', type: 'ioc', position: { x: 200, y: 250 }, data: { label: 'evil-domain.ru', type: 'Domain' } },
  { id: '3', type: 'ioc', position: { x: 400, y: 250 }, data: { label: '185.234.72.123', type: 'IP Address' } },
  { id: '4', type: 'ioc', position: { x: 600, y: 250 }, data: { label: 'malware.exe', type: 'File Hash' } },
  { id: '5', type: 'actor', position: { x: 400, y: 0 }, data: { label: 'Cozy Bear', group: 'APT29' } },
  { id: '6', type: 'asset', position: { x: 200, y: 400 }, data: { label: 'DC-01', type: 'Domain Controller' } },
  { id: '7', type: 'asset', position: { x: 400, y: 400 }, data: { label: 'WS-05', type: 'Workstation' } },
  { id: '8', type: 'asset', position: { x: 600, y: 400 }, data: { label: 'SRV-DB', type: 'Database Server' } },
  { id: '9', type: 'evidence', position: { x: 100, y: 300 }, data: { label: 'Memory Dump', case: 'CASE-2025-001' } },
  { id: '10', type: 'evidence', position: { x: 700, y: 300 }, data: { label: 'Network Capture', case: 'CASE-2025-001' } },
]

const initialEdges: Edge[] = [
  { id: 'e1-2', source: '1', target: '2', label: 'uses', style: { stroke: '#ff4444' }, animated: true },
  { id: 'e1-3', source: '1', target: '3', label: 'uses', style: { stroke: '#ff4444' }, animated: true },
  { id: 'e1-4', source: '1', target: '4', label: 'deploys', style: { stroke: '#ff4444' }, animated: true },
  { id: 'e5-1', source: '5', target: '1', label: 'attributed', style: { stroke: '#aa44ff' } },
  { id: 'e2-6', source: '2', target: '6', label: 'contacted', style: { stroke: '#44aaff' } },
  { id: 'e3-7', source: '3', target: '7', label: 'connected', style: { stroke: '#44aaff' } },
  { id: 'e4-8', source: '4', target: '8', label: 'found on', style: { stroke: '#44aaff' } },
  { id: 'e9-7', source: '9', target: '7', label: 'from', style: { stroke: '#44ff44' } },
  { id: 'e10-3', source: '10', target: '3', label: 'captures', style: { stroke: '#44ff44' } },
]

export default function KnowledgeGraph() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)
  const [searchQuery, setSearchQuery] = useState('')

  const onConnect = useCallback(
    (connection: Connection) => setEdges((eds) => addEdge({ ...connection, animated: true }, eds)),
    [setEdges]
  )

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNode(node)
  }

  const filteredNodes = useMemo(() => {
    if (!searchQuery) return nodes
    return nodes.filter(node =>
      node.data.label.toLowerCase().includes(searchQuery.toLowerCase())
    )
  }, [nodes, searchQuery])

  const addNode = (type: string) => {
    const newNode: Node = {
      id: `node-${Date.now()}`,
      type,
      position: { x: Math.random() * 400 + 200, y: Math.random() * 300 + 100 },
      data: {
        label: `New ${type}`,
        type: type,
        severity: 'Medium',
        group: 'Unknown',
        case: 'CASE-NEW'
      }
    }
    setNodes((nds) => [...nds, newNode])
  }

  return (
    <div className="h-full flex">
      {/* Graph canvas */}
      <div className="flex-1 relative">
        <ReactFlow
          nodes={filteredNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          fitView
          className="bg-null-bg"
        >
          <Background variant={BackgroundVariant.Dots} color="#1a1a2e" gap={20} />
          <Controls className="bg-null-surface border border-null-border rounded" />
          <MiniMap
            nodeColor={(node) => {
              switch (node.type) {
                case 'ioc': return '#ef4444'
                case 'threat': return '#f97316'
                case 'asset': return '#06b6d4'
                case 'actor': return '#a855f7'
                case 'evidence': return '#22c55e'
                default: return '#555'
              }
            }}
            className="bg-null-surface border border-null-border rounded"
          />
        </ReactFlow>

        {/* Toolbar */}
        <div className="absolute top-4 left-4 flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-null-surface/90 border border-null-border">
            <Search className="w-4 h-4 text-null-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search nodes..."
              className="bg-transparent text-sm text-null-text placeholder:text-null-muted outline-none w-40"
            />
          </div>

          <div className="flex items-center gap-1 px-2 py-1.5 rounded-lg bg-null-surface/90 border border-null-border">
            {[
              { type: 'ioc', icon: Bug, color: 'text-red-400' },
              { type: 'threat', icon: AlertTriangle, color: 'text-orange-400' },
              { type: 'asset', icon: Server, color: 'text-cyan-400' },
              { type: 'actor', icon: User, color: 'text-purple-400' },
              { type: 'evidence', icon: FileText, color: 'text-green-400' },
            ].map((item) => (
              <button
                key={item.type}
                onClick={() => addNode(item.type)}
                className={`p-1.5 rounded hover:bg-null-border/50 ${item.color}`}
                title={`Add ${item.type}`}
              >
                <item.icon className="w-4 h-4" />
              </button>
            ))}
          </div>
        </div>

        {/* Stats */}
        <div className="absolute bottom-4 left-4 flex items-center gap-3 px-3 py-2 rounded-lg bg-null-surface/90 border border-null-border text-xs">
          <span className="text-red-400">{nodes.filter(n => n.type === 'ioc').length} IOCs</span>
          <span className="text-orange-400">{nodes.filter(n => n.type === 'threat').length} Threats</span>
          <span className="text-cyan-400">{nodes.filter(n => n.type === 'asset').length} Assets</span>
          <span className="text-purple-400">{nodes.filter(n => n.type === 'actor').length} Actors</span>
          <span className="text-green-400">{nodes.filter(n => n.type === 'evidence').length} Evidence</span>
        </div>
      </div>

      {/* Right panel - Node details */}
      {selectedNode && (
        <motion.div
          initial={{ x: 300, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          className="w-80 border-l border-null-border bg-null-surface/50 p-4"
        >
          <h3 className="font-display text-sm mb-4">Node Details</h3>

          <div className="space-y-4">
            <div>
              <label className="text-xs text-null-muted">Type</label>
              <p className="text-sm text-null-text capitalize">{selectedNode.type}</p>
            </div>

            <div>
              <label className="text-xs text-null-muted">Label</label>
              <input
                type="text"
                value={selectedNode.data.label}
                onChange={(e) => {
                  setNodes(nds => nds.map(n =>
                    n.id === selectedNode.id
                      ? { ...n, data: { ...n.data, label: e.target.value } }
                      : n
                  ))
                }}
                className="w-full mt-1 px-2 py-1.5 rounded bg-null-bg/50 border border-null-border text-sm text-null-text"
              />
            </div>

            <div>
              <label className="text-xs text-null-muted">Connected Nodes</label>
              <div className="mt-1 space-y-1">
                {edges
                  .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                  .map(e => {
                    const connectedId = e.source === selectedNode.id ? e.target : e.source
                    const connectedNode = nodes.find(n => n.id === connectedId)
                    return (
                      <div key={e.id} className="text-xs px-2 py-1 rounded bg-null-bg/50 flex items-center justify-between">
                        <span className="text-null-text">{connectedNode?.data.label}</span>
                        <span className="text-null-muted">{e.label}</span>
                      </div>
                    )
                  })}
              </div>
            </div>

            <div className="pt-4 border-t border-null-border">
              <button className="w-full px-3 py-2 rounded bg-null-primary/20 text-null-primary text-sm">
                Expand Relationships
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}
