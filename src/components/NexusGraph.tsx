import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import ForceGraph3D from 'react-force-graph-3d'
import {
  Network, Target, Shield, Zap, AlertTriangle, Eye, Play, Pause,
  RotateCcw, ZoomIn, ZoomOut, Maximize2, Filter, Download, Share2,
  Brain, Crosshair, Clock, Radio, Activity
} from 'lucide-react'
import * as THREE from 'three'

// STIX 2.1 Compliant Node Types with visual config
const NODE_TYPES = {
  'threat-actor': { color: '#ff0040', size: 12, shape: 'skull', glow: true },
  'malware': { color: '#ff6b00', size: 10, shape: 'virus', glow: true },
  'attack-pattern': { color: '#ff0080', size: 8, shape: 'diamond', glow: false },
  'campaign': { color: '#a855f7', size: 11, shape: 'flag', glow: true },
  'indicator': { color: '#22d3ee', size: 6, shape: 'circle', glow: false },
  'infrastructure': { color: '#3b82f6', size: 9, shape: 'server', glow: false },
  'tool': { color: '#eab308', size: 7, shape: 'wrench', glow: false },
  'vulnerability': { color: '#ef4444', size: 8, shape: 'triangle', glow: true },
  'identity': { color: '#10b981', size: 8, shape: 'user', glow: false },
  'intrusion-set': { color: '#ec4899', size: 11, shape: 'target', glow: true },
  'course-of-action': { color: '#06b6d4', size: 7, shape: 'shield', glow: false },
  'location': { color: '#6366f1', size: 6, shape: 'pin', glow: false },
  'observed-data': { color: '#84cc16', size: 5, shape: 'dot', glow: false },
}

// MITRE ATT&CK Tactics for kill chain visualization
const MITRE_TACTICS = [
  { id: 'reconnaissance', name: 'Reconnaissance', color: '#64748b', x: -400 },
  { id: 'resource-development', name: 'Resource Development', color: '#78716c', x: -300 },
  { id: 'initial-access', name: 'Initial Access', color: '#dc2626', x: -200 },
  { id: 'execution', name: 'Execution', color: '#ea580c', x: -100 },
  { id: 'persistence', name: 'Persistence', color: '#d97706', x: 0 },
  { id: 'privilege-escalation', name: 'Privilege Escalation', color: '#ca8a04', x: 100 },
  { id: 'defense-evasion', name: 'Defense Evasion', color: '#65a30d', x: 200 },
  { id: 'credential-access', name: 'Credential Access', color: '#16a34a', x: 300 },
  { id: 'discovery', name: 'Discovery', color: '#0d9488', x: 400 },
  { id: 'lateral-movement', name: 'Lateral Movement', color: '#0891b2', x: 500 },
  { id: 'collection', name: 'Collection', color: '#2563eb', x: 600 },
  { id: 'exfiltration', name: 'Exfiltration', color: '#7c3aed', x: 700 },
  { id: 'impact', name: 'Impact', color: '#db2777', x: 800 },
]

interface GraphNode {
  id: string
  name: string
  type: keyof typeof NODE_TYPES
  tactic?: string
  technique?: string
  description?: string
  confidence?: number
  firstSeen?: string
  lastSeen?: string
  x?: number
  y?: number
  z?: number
  fx?: number
  fy?: number
  fz?: number
}

interface GraphLink {
  source: string | GraphNode
  target: string | GraphNode
  relationship: string
  confidence?: number
  animated?: boolean
}

interface AttackPath {
  id: string
  name: string
  nodes: string[]
  severity: 'critical' | 'high' | 'medium' | 'low'
  probability: number
}

// Demo data - APT29 (Cozy Bear) attack simulation
const DEMO_DATA = {
  nodes: [
    { id: 'apt29', name: 'APT29 (Cozy Bear)', type: 'threat-actor' as const, description: 'Russian state-sponsored threat group', confidence: 95 },
    { id: 'wellmess', name: 'WellMess', type: 'malware' as const, tactic: 'execution', technique: 'T1059', confidence: 90 },
    { id: 'wellmail', name: 'WellMail', type: 'malware' as const, tactic: 'execution', technique: 'T1059', confidence: 88 },
    { id: 'sunburst', name: 'SUNBURST', type: 'malware' as const, tactic: 'initial-access', technique: 'T1195.002', confidence: 98 },
    { id: 'teardrop', name: 'TEARDROP', type: 'malware' as const, tactic: 'defense-evasion', technique: 'T1027', confidence: 92 },
    { id: 'raindrop', name: 'Raindrop', type: 'malware' as const, tactic: 'lateral-movement', technique: 'T1021', confidence: 85 },
    { id: 'nobelium-c2', name: 'NOBELIUM C2', type: 'infrastructure' as const, description: 'Command & control infrastructure', confidence: 87 },
    { id: 'spear-phish', name: 'Spear Phishing', type: 'attack-pattern' as const, tactic: 'initial-access', technique: 'T1566.001', confidence: 95 },
    { id: 'supply-chain', name: 'Supply Chain Compromise', type: 'attack-pattern' as const, tactic: 'initial-access', technique: 'T1195.002', confidence: 98 },
    { id: 'solarwinds', name: 'SolarWinds Orion', type: 'vulnerability' as const, description: 'CVE-2020-10148', confidence: 99 },
    { id: 'gov-target', name: 'US Government Agencies', type: 'identity' as const, description: 'Primary targets', confidence: 95 },
    { id: 'tech-target', name: 'Technology Sector', type: 'identity' as const, description: 'Secondary targets', confidence: 90 },
    { id: 'data-exfil', name: 'Data Exfiltration', type: 'attack-pattern' as const, tactic: 'exfiltration', technique: 'T1041', confidence: 88 },
    { id: 'credential-dump', name: 'Credential Dumping', type: 'attack-pattern' as const, tactic: 'credential-access', technique: 'T1003', confidence: 92 },
    { id: 'defense-block', name: 'Network Segmentation', type: 'course-of-action' as const, description: 'Recommended mitigation', confidence: 100 },
    { id: 'indicator-1', name: '185.225.69[.]69', type: 'indicator' as const, description: 'C2 IP Address', confidence: 95 },
    { id: 'indicator-2', name: 'avsvmcloud[.]com', type: 'indicator' as const, description: 'C2 Domain', confidence: 97 },
    { id: 'campaign-1', name: 'SolarWinds Campaign', type: 'campaign' as const, firstSeen: '2020-03-01', lastSeen: '2020-12-13', confidence: 99 },
  ],
  links: [
    { source: 'apt29', target: 'campaign-1', relationship: 'attributed-to' },
    { source: 'campaign-1', target: 'sunburst', relationship: 'uses', animated: true },
    { source: 'campaign-1', target: 'teardrop', relationship: 'uses', animated: true },
    { source: 'campaign-1', target: 'raindrop', relationship: 'uses' },
    { source: 'sunburst', target: 'solarwinds', relationship: 'exploits', animated: true },
    { source: 'sunburst', target: 'supply-chain', relationship: 'uses' },
    { source: 'apt29', target: 'wellmess', relationship: 'uses' },
    { source: 'apt29', target: 'wellmail', relationship: 'uses' },
    { source: 'apt29', target: 'nobelium-c2', relationship: 'uses' },
    { source: 'nobelium-c2', target: 'indicator-1', relationship: 'indicates' },
    { source: 'nobelium-c2', target: 'indicator-2', relationship: 'indicates' },
    { source: 'apt29', target: 'spear-phish', relationship: 'uses' },
    { source: 'campaign-1', target: 'gov-target', relationship: 'targets', animated: true },
    { source: 'campaign-1', target: 'tech-target', relationship: 'targets' },
    { source: 'teardrop', target: 'credential-dump', relationship: 'uses' },
    { source: 'raindrop', target: 'data-exfil', relationship: 'uses' },
    { source: 'defense-block', target: 'data-exfil', relationship: 'mitigates' },
    { source: 'defense-block', target: 'raindrop', relationship: 'mitigates' },
  ],
  attackPaths: [
    {
      id: 'path-1',
      name: 'SolarWinds Supply Chain Attack',
      nodes: ['apt29', 'campaign-1', 'sunburst', 'solarwinds', 'gov-target'],
      severity: 'critical',
      probability: 0.95,
    },
    {
      id: 'path-2',
      name: 'Lateral Movement to Exfiltration',
      nodes: ['sunburst', 'teardrop', 'credential-dump', 'raindrop', 'data-exfil'],
      severity: 'high',
      probability: 0.78,
    },
  ] as AttackPath[],
}

export default function NexusGraph() {
  const graphRef = useRef<any>(null)
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; links: GraphLink[] }>({
    nodes: DEMO_DATA.nodes,
    links: DEMO_DATA.links,
  })
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [isSimulating, setIsSimulating] = useState(false)
  const [simulationStep, setSimulationStep] = useState(0)
  const [showTactics, setShowTactics] = useState(true)
  const [filterTypes, setFilterTypes] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<'3d' | 'timeline' | 'killchain'>('3d')
  const [highlightNodes, setHighlightNodes] = useState<Set<string>>(new Set())
  const [highlightLinks, setHighlightLinks] = useState<Set<string>>(new Set())

  // Particle system for animated links
  const particlePositions = useRef<Map<string, number>>(new Map())

  // Filter nodes based on type selection
  const filteredData = useMemo(() => {
    if (filterTypes.size === 0) return graphData
    const visibleNodes = graphData.nodes.filter(n => filterTypes.has(n.type))
    const visibleNodeIds = new Set(visibleNodes.map(n => n.id))
    const visibleLinks = graphData.links.filter(l => {
      const sourceId = typeof l.source === 'string' ? l.source : l.source.id
      const targetId = typeof l.target === 'string' ? l.target : l.target.id
      return visibleNodeIds.has(sourceId) && visibleNodeIds.has(targetId)
    })
    return { nodes: visibleNodes, links: visibleLinks }
  }, [graphData, filterTypes])

  // Node visual representation
  const nodeThreeObject = useCallback((node: GraphNode) => {
    const config = NODE_TYPES[node.type] || NODE_TYPES['indicator']
    const isHighlighted = highlightNodes.has(node.id)
    const isSelected = selectedNode?.id === node.id

    // Create group for node
    const group = new THREE.Group()

    // Main sphere
    const geometry = new THREE.SphereGeometry(config.size * (isHighlighted ? 1.5 : 1), 32, 32)
    const material = new THREE.MeshPhongMaterial({
      color: config.color,
      emissive: config.glow || isHighlighted ? config.color : 0x000000,
      emissiveIntensity: isHighlighted ? 0.8 : config.glow ? 0.3 : 0,
      transparent: true,
      opacity: 0.9,
    })
    const sphere = new THREE.Mesh(geometry, material)
    group.add(sphere)

    // Outer glow ring for selected/highlighted nodes
    if (isSelected || isHighlighted) {
      const ringGeometry = new THREE.RingGeometry(config.size * 1.5, config.size * 2, 32)
      const ringMaterial = new THREE.MeshBasicMaterial({
        color: isSelected ? '#00ff88' : config.color,
        transparent: true,
        opacity: 0.5,
        side: THREE.DoubleSide,
      })
      const ring = new THREE.Mesh(ringGeometry, ringMaterial)
      ring.rotation.x = Math.PI / 2
      group.add(ring)

      // Pulsing animation ring
      const pulseRingGeometry = new THREE.RingGeometry(config.size * 2, config.size * 2.5, 32)
      const pulseRingMaterial = new THREE.MeshBasicMaterial({
        color: '#00ff88',
        transparent: true,
        opacity: 0.3,
        side: THREE.DoubleSide,
      })
      const pulseRing = new THREE.Mesh(pulseRingGeometry, pulseRingMaterial)
      pulseRing.rotation.x = Math.PI / 2
      group.add(pulseRing)
    }

    // Add label sprite
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')!
    canvas.width = 256
    canvas.height = 64
    ctx.fillStyle = 'rgba(0, 0, 0, 0.7)'
    ctx.fillRect(0, 0, 256, 64)
    ctx.strokeStyle = config.color
    ctx.lineWidth = 2
    ctx.strokeRect(0, 0, 256, 64)
    ctx.fillStyle = '#ffffff'
    ctx.font = 'bold 20px monospace'
    ctx.textAlign = 'center'
    ctx.fillText(node.name.substring(0, 20), 128, 40)

    const texture = new THREE.CanvasTexture(canvas)
    const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true })
    const sprite = new THREE.Sprite(spriteMaterial)
    sprite.scale.set(40, 10, 1)
    sprite.position.y = config.size + 15
    group.add(sprite)

    return group
  }, [highlightNodes, selectedNode])

  // Link visual representation
  const linkThreeObject = useCallback((link: GraphLink) => {
    const isHighlighted = highlightLinks.has(`${typeof link.source === 'string' ? link.source : link.source.id}-${typeof link.target === 'string' ? link.target : link.target.id}`)

    // For animated links, create particle system
    if (link.animated) {
      const group = new THREE.Group()

      // Glowing line
      const material = new THREE.LineBasicMaterial({
        color: isHighlighted ? '#00ff88' : '#ff0080',
        transparent: true,
        opacity: 0.8,
      })

      return group
    }
    return undefined
  }, [highlightLinks])

  // Handle node click
  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node)

    // Highlight connected nodes and links
    const connectedNodes = new Set<string>([node.id])
    const connectedLinks = new Set<string>()

    graphData.links.forEach(link => {
      const sourceId = typeof link.source === 'string' ? link.source : link.source.id
      const targetId = typeof link.target === 'string' ? link.target : link.target.id

      if (sourceId === node.id || targetId === node.id) {
        connectedNodes.add(sourceId)
        connectedNodes.add(targetId)
        connectedLinks.add(`${sourceId}-${targetId}`)
      }
    })

    setHighlightNodes(connectedNodes)
    setHighlightLinks(connectedLinks)

    // Focus camera on node
    if (graphRef.current) {
      const distance = 200
      const distRatio = 1 + distance / Math.hypot(node.x || 0, node.y || 0, node.z || 0)
      graphRef.current.cameraPosition(
        { x: (node.x || 0) * distRatio, y: (node.y || 0) * distRatio, z: (node.z || 0) * distRatio },
        node,
        1000
      )
    }
  }, [graphData.links])

  // Attack path simulation
  const startSimulation = useCallback(() => {
    if (!selectedPath) return
    setIsSimulating(true)
    setSimulationStep(0)
  }, [selectedPath])

  useEffect(() => {
    if (!isSimulating || !selectedPath) return

    const interval = setInterval(() => {
      setSimulationStep(prev => {
        if (prev >= selectedPath.nodes.length - 1) {
          setIsSimulating(false)
          return prev
        }

        // Highlight current and previous nodes in path
        const currentNodes = new Set(selectedPath.nodes.slice(0, prev + 2))
        setHighlightNodes(currentNodes)

        // Focus on current node
        const currentNodeId = selectedPath.nodes[prev + 1]
        const node = graphData.nodes.find(n => n.id === currentNodeId)
        if (node && graphRef.current) {
          const distance = 150
          const distRatio = 1 + distance / Math.hypot(node.x || 0, node.y || 0, node.z || 0)
          graphRef.current.cameraPosition(
            { x: (node.x || 0) * distRatio, y: (node.y || 0) * distRatio, z: (node.z || 0) * distRatio },
            node,
            800
          )
        }

        return prev + 1
      })
    }, 1500)

    return () => clearInterval(interval)
  }, [isSimulating, selectedPath, graphData.nodes])

  // Reset view
  const resetView = useCallback(() => {
    setSelectedNode(null)
    setSelectedPath(null)
    setHighlightNodes(new Set())
    setHighlightLinks(new Set())
    setIsSimulating(false)
    setSimulationStep(0)
    if (graphRef.current) {
      graphRef.current.cameraPosition({ x: 0, y: 0, z: 500 }, { x: 0, y: 0, z: 0 }, 1000)
    }
  }, [])

  // Export graph as image
  const exportGraph = useCallback(() => {
    if (!graphRef.current) return
    const link = document.createElement('a')
    link.download = 'nexus-attack-graph.png'
    // Note: In real implementation, would capture WebGL context
    alert('Export functionality - would capture 3D view as image')
  }, [])

  return (
    <div className="h-full flex bg-null-bg">
      {/* Main 3D View */}
      <div className="flex-1 relative">
        {/* Sci-fi frame overlay */}
        <div className="absolute inset-0 pointer-events-none z-10">
          {/* Corner brackets */}
          <div className="absolute top-4 left-4 w-16 h-16 border-l-2 border-t-2 border-cyan-500/50" />
          <div className="absolute top-4 right-4 w-16 h-16 border-r-2 border-t-2 border-cyan-500/50" />
          <div className="absolute bottom-4 left-4 w-16 h-16 border-l-2 border-b-2 border-cyan-500/50" />
          <div className="absolute bottom-4 right-4 w-16 h-16 border-r-2 border-b-2 border-cyan-500/50" />

          {/* Scan line effect */}
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-cyan-500/5 to-transparent animate-scan" />

          {/* HUD elements */}
          <div className="absolute top-4 left-1/2 -translate-x-1/2 flex items-center gap-4 text-xs font-mono">
            <div className="px-3 py-1 bg-black/60 border border-cyan-500/30 rounded">
              <span className="text-cyan-400">NEXUS</span>
              <span className="text-null-muted ml-2">// THREAT TOPOLOGY</span>
            </div>
            <div className="px-3 py-1 bg-black/60 border border-cyan-500/30 rounded flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-green-400">LIVE</span>
            </div>
          </div>

          {/* Stats overlay */}
          <div className="absolute bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-6 text-xs font-mono">
            <div className="text-cyan-400">
              NODES: <span className="text-white">{filteredData.nodes.length}</span>
            </div>
            <div className="text-cyan-400">
              LINKS: <span className="text-white">{filteredData.links.length}</span>
            </div>
            <div className="text-cyan-400">
              PATHS: <span className="text-white">{DEMO_DATA.attackPaths.length}</span>
            </div>
          </div>
        </div>

        {/* 3D Force Graph */}
        <ForceGraph3D
          ref={graphRef}
          graphData={filteredData}
          nodeThreeObject={nodeThreeObject}
          nodeThreeObjectExtend={false}
          linkWidth={link => highlightLinks.has(`${typeof link.source === 'string' ? link.source : (link.source as GraphNode).id}-${typeof link.target === 'string' ? link.target : (link.target as GraphNode).id}`) ? 3 : 1}
          linkColor={link => {
            const sourceId = typeof link.source === 'string' ? link.source : (link.source as GraphNode).id
            const targetId = typeof link.target === 'string' ? link.target : (link.target as GraphNode).id
            return highlightLinks.has(`${sourceId}-${targetId}`) ? '#00ff88' : link.animated ? '#ff0080' : '#334155'
          }}
          linkOpacity={0.6}
          linkDirectionalParticles={link => link.animated ? 4 : 0}
          linkDirectionalParticleWidth={3}
          linkDirectionalParticleSpeed={0.005}
          linkDirectionalParticleColor={() => '#ff0080'}
          onNodeClick={handleNodeClick}
          onBackgroundClick={() => {
            setSelectedNode(null)
            setHighlightNodes(new Set())
            setHighlightLinks(new Set())
          }}
          backgroundColor="#0a0a0f"
          showNavInfo={false}
        />

        {/* Control panel */}
        <div className="absolute top-20 left-4 flex flex-col gap-2">
          <button
            onClick={resetView}
            className="p-2 bg-null-surface/80 border border-null-border rounded hover:border-cyan-500/50 transition-colors"
            title="Reset View"
          >
            <RotateCcw className="w-4 h-4 text-null-muted" />
          </button>
          <button
            onClick={() => graphRef.current?.zoomToFit(400)}
            className="p-2 bg-null-surface/80 border border-null-border rounded hover:border-cyan-500/50 transition-colors"
            title="Fit to View"
          >
            <Maximize2 className="w-4 h-4 text-null-muted" />
          </button>
          <button
            onClick={exportGraph}
            className="p-2 bg-null-surface/80 border border-null-border rounded hover:border-cyan-500/50 transition-colors"
            title="Export"
          >
            <Download className="w-4 h-4 text-null-muted" />
          </button>
        </div>
      </div>

      {/* Right Panel - Node Details & Attack Paths */}
      <div className="w-80 bg-null-surface border-l border-null-border flex flex-col">
        {/* Panel Header */}
        <div className="p-4 border-b border-null-border">
          <div className="flex items-center gap-2 text-sm font-medium text-null-text">
            <Brain className="w-4 h-4 text-cyan-400" />
            <span>THREAT INTELLIGENCE</span>
          </div>
        </div>

        {/* Node Details */}
        <AnimatePresence mode="wait">
          {selectedNode ? (
            <motion.div
              key="node-details"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="p-4 border-b border-null-border"
            >
              <div className="flex items-start gap-3">
                <div
                  className="w-10 h-10 rounded-lg flex items-center justify-center"
                  style={{ backgroundColor: `${NODE_TYPES[selectedNode.type]?.color}20`, borderColor: NODE_TYPES[selectedNode.type]?.color, borderWidth: 1 }}
                >
                  <Target className="w-5 h-5" style={{ color: NODE_TYPES[selectedNode.type]?.color }} />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-sm font-medium text-null-text truncate">{selectedNode.name}</h3>
                  <p className="text-xs text-null-muted capitalize">{selectedNode.type.replace('-', ' ')}</p>
                </div>
              </div>

              {selectedNode.description && (
                <p className="mt-3 text-xs text-null-muted">{selectedNode.description}</p>
              )}

              <div className="mt-4 grid grid-cols-2 gap-2">
                {selectedNode.technique && (
                  <div className="p-2 bg-null-bg rounded border border-null-border">
                    <div className="text-[10px] text-null-muted uppercase">Technique</div>
                    <div className="text-xs text-red-400 font-mono">{selectedNode.technique}</div>
                  </div>
                )}
                {selectedNode.tactic && (
                  <div className="p-2 bg-null-bg rounded border border-null-border">
                    <div className="text-[10px] text-null-muted uppercase">Tactic</div>
                    <div className="text-xs text-purple-400 font-mono capitalize">{selectedNode.tactic.replace('-', ' ')}</div>
                  </div>
                )}
                {selectedNode.confidence !== undefined && (
                  <div className="p-2 bg-null-bg rounded border border-null-border">
                    <div className="text-[10px] text-null-muted uppercase">Confidence</div>
                    <div className="text-xs text-cyan-400">{selectedNode.confidence}%</div>
                  </div>
                )}
                {selectedNode.firstSeen && (
                  <div className="p-2 bg-null-bg rounded border border-null-border">
                    <div className="text-[10px] text-null-muted uppercase">First Seen</div>
                    <div className="text-xs text-null-text">{selectedNode.firstSeen}</div>
                  </div>
                )}
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="no-selection"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-4 border-b border-null-border"
            >
              <div className="text-center py-8 text-null-muted">
                <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p className="text-xs">Click a node to view details</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Attack Paths */}
        <div className="flex-1 overflow-auto">
          <div className="p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-medium text-null-muted uppercase tracking-wider">Attack Paths</h4>
              <span className="text-[10px] text-null-muted">{DEMO_DATA.attackPaths.length} identified</span>
            </div>

            <div className="space-y-2">
              {DEMO_DATA.attackPaths.map(path => (
                <button
                  key={path.id}
                  onClick={() => setSelectedPath(path)}
                  className={`w-full p-3 rounded-lg border transition-all text-left ${
                    selectedPath?.id === path.id
                      ? 'bg-null-primary/10 border-null-primary/50'
                      : 'bg-null-bg border-null-border hover:border-null-border/80'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <Crosshair className="w-3 h-3 text-red-400" />
                        <span className="text-xs font-medium text-null-text truncate">{path.name}</span>
                      </div>
                      <div className="mt-2 flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                          path.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                          path.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                          path.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-blue-500/20 text-blue-400'
                        }`}>
                          {path.severity.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-null-muted">{path.nodes.length} nodes</span>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] text-null-muted">Probability</div>
                      <div className="text-sm font-mono text-cyan-400">{(path.probability * 100).toFixed(0)}%</div>
                    </div>
                  </div>

                  {/* Path visualization mini */}
                  <div className="mt-3 flex items-center gap-1">
                    {path.nodes.map((nodeId, idx) => {
                      const node = DEMO_DATA.nodes.find(n => n.id === nodeId)
                      return (
                        <div key={nodeId} className="flex items-center">
                          <div
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: NODE_TYPES[node?.type || 'indicator']?.color }}
                            title={node?.name}
                          />
                          {idx < path.nodes.length - 1 && (
                            <div className="w-3 h-px bg-null-border" />
                          )}
                        </div>
                      )
                    })}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Simulation Controls */}
        {selectedPath && (
          <div className="p-4 border-t border-null-border bg-null-bg">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-null-muted">Attack Simulation</span>
              <span className="text-xs text-cyan-400">
                {isSimulating ? `Step ${simulationStep + 1}/${selectedPath.nodes.length}` : 'Ready'}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={isSimulating ? () => setIsSimulating(false) : startSimulation}
                className={`flex-1 py-2 rounded flex items-center justify-center gap-2 transition-colors ${
                  isSimulating
                    ? 'bg-red-500/20 border border-red-500/50 text-red-400'
                    : 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/30'
                }`}
              >
                {isSimulating ? (
                  <>
                    <Pause className="w-4 h-4" />
                    <span className="text-xs">Stop</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span className="text-xs">Simulate</span>
                  </>
                )}
              </button>
              <button
                onClick={resetView}
                className="px-3 py-2 rounded bg-null-surface border border-null-border text-null-muted hover:text-null-text transition-colors"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Type Legend */}
        <div className="p-4 border-t border-null-border">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs font-medium text-null-muted uppercase tracking-wider">Entity Types</h4>
            <button
              onClick={() => setFilterTypes(new Set())}
              className="text-[10px] text-cyan-400 hover:underline"
            >
              Clear Filters
            </button>
          </div>
          <div className="grid grid-cols-2 gap-1">
            {Object.entries(NODE_TYPES).slice(0, 8).map(([type, config]) => (
              <button
                key={type}
                onClick={() => {
                  const newFilters = new Set(filterTypes)
                  if (newFilters.has(type)) {
                    newFilters.delete(type)
                  } else {
                    newFilters.add(type)
                  }
                  setFilterTypes(newFilters)
                }}
                className={`flex items-center gap-2 px-2 py-1 rounded text-[10px] transition-colors ${
                  filterTypes.size === 0 || filterTypes.has(type)
                    ? 'opacity-100'
                    : 'opacity-40'
                }`}
              >
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: config.color }}
                />
                <span className="text-null-muted capitalize truncate">{type.replace('-', ' ')}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* CSS for scan line animation */}
      <style>{`
        @keyframes scan {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100%); }
        }
        .animate-scan {
          animation: scan 4s linear infinite;
        }
      `}</style>
    </div>
  )
}
