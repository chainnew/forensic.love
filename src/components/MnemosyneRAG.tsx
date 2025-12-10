import { useState, useCallback, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Brain, Search, Database, FileText, Upload, Trash2, Plus,
  Sparkles, Link2, Clock, Tag, Zap, BookOpen, AlertTriangle,
  ChevronDown, ChevronRight, Download, RefreshCw, Settings
} from 'lucide-react'

// Simple vector operations for browser-based semantic search
function cosineSimilarity(a: number[], b: number[]): number {
  let dotProduct = 0
  let normA = 0
  let normB = 0
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i]
    normA += a[i] * a[i]
    normB += b[i] * b[i]
  }
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB))
}

// Simple word-based embedding (TF-IDF style for demo)
function createEmbedding(text: string, vocabulary: string[]): number[] {
  const words = text.toLowerCase().split(/\W+/).filter(w => w.length > 2)
  const wordCounts = new Map<string, number>()

  words.forEach(word => {
    wordCounts.set(word, (wordCounts.get(word) || 0) + 1)
  })

  return vocabulary.map(vocabWord => {
    const count = wordCounts.get(vocabWord) || 0
    return count / (words.length || 1)
  })
}

// Build vocabulary from documents
function buildVocabulary(documents: string[]): string[] {
  const wordSet = new Set<string>()
  documents.forEach(doc => {
    doc.toLowerCase().split(/\W+/).filter(w => w.length > 2).forEach(word => wordSet.add(word))
  })
  return Array.from(wordSet).slice(0, 500) // Limit vocab size
}

interface Document {
  id: string
  title: string
  content: string
  type: 'report' | 'ioc' | 'note' | 'alert' | 'technique' | 'threat-actor'
  tags: string[]
  timestamp: number
  embedding?: number[]
  source?: string
  confidence?: number
}

interface SearchResult {
  document: Document
  similarity: number
  highlights: string[]
}

interface RAGResponse {
  answer: string
  sources: Document[]
  confidence: number
  reasoning: string[]
}

// Demo documents
const DEMO_DOCUMENTS: Document[] = [
  {
    id: 'doc-1',
    title: 'APT29 SUNBURST Analysis',
    content: 'APT29, also known as Cozy Bear, deployed SUNBURST malware through SolarWinds Orion software supply chain compromise. The attack vector exploited legitimate update mechanisms to distribute malicious DLL files. Initial access was achieved through trojanized software updates. Persistence was maintained through scheduled tasks and registry modifications.',
    type: 'report',
    tags: ['apt29', 'sunburst', 'supply-chain', 'solarwinds'],
    timestamp: Date.now() - 86400000 * 30,
    source: 'Internal Threat Intel',
    confidence: 95
  },
  {
    id: 'doc-2',
    title: 'Cobalt Strike Beacon Detection',
    content: 'Cobalt Strike beacons were detected communicating with C2 infrastructure at 185.225.69.69. The beacon used HTTPS with custom malleable C2 profile. Process injection observed in explorer.exe and svchost.exe. Memory scanning revealed typical Cobalt Strike shellcode patterns.',
    type: 'alert',
    tags: ['cobalt-strike', 'c2', 'beacon', 'process-injection'],
    timestamp: Date.now() - 86400000 * 5,
    source: 'EDR Alert',
    confidence: 88
  },
  {
    id: 'doc-3',
    title: 'T1059.001 - PowerShell Execution',
    content: 'MITRE ATT&CK Technique T1059.001 describes adversaries abusing PowerShell commands for execution. Common patterns include encoded commands, bypass of execution policy, downloading remote scripts, and fileless malware execution. Detection involves monitoring command-line parameters and script block logging.',
    type: 'technique',
    tags: ['mitre', 'powershell', 'execution', 't1059'],
    timestamp: Date.now() - 86400000 * 90,
    source: 'MITRE ATT&CK',
    confidence: 100
  },
  {
    id: 'doc-4',
    title: 'FIN7 TTPs Summary',
    content: 'FIN7 threat group targets financial and retail sectors using spear-phishing with malicious documents. They employ Carbanak and Cobalt Strike for post-exploitation. Known for sophisticated social engineering and persistence through scheduled tasks. Often uses legitimate tools like PowerShell and WMI for lateral movement.',
    type: 'threat-actor',
    tags: ['fin7', 'carbanak', 'financial', 'spear-phishing'],
    timestamp: Date.now() - 86400000 * 60,
    source: 'FBI Flash',
    confidence: 92
  },
  {
    id: 'doc-5',
    title: 'IOC Feed - March 2024',
    content: 'Malicious domains: evil-update.com, backdoor-c2.net. IP addresses: 192.168.1.100 (internal pivot), 45.77.65.211 (external C2). File hashes: SHA256 abc123def456... associated with Emotet. Email indicators: invoice-12345@malicious.com sending weaponized attachments.',
    type: 'ioc',
    tags: ['ioc', 'emotet', 'c2', 'malware'],
    timestamp: Date.now() - 86400000 * 2,
    source: 'Threat Feed',
    confidence: 85
  },
  {
    id: 'doc-6',
    title: 'Incident Response Notes - Server Compromise',
    content: 'Compromised server DC01 showed signs of credential harvesting. LSASS memory dump detected via Task Manager. Attacker created shadow admin account "admin$". Lateral movement to SQL server observed. Recommend immediate password reset and network isolation.',
    type: 'note',
    tags: ['incident-response', 'credential-theft', 'lateral-movement'],
    timestamp: Date.now() - 86400000 * 1,
    source: 'SOC Analyst',
    confidence: 90
  }
]

const TYPE_CONFIG = {
  'report': { color: 'text-purple-400', bg: 'bg-purple-500/20', icon: FileText },
  'ioc': { color: 'text-red-400', bg: 'bg-red-500/20', icon: AlertTriangle },
  'note': { color: 'text-blue-400', bg: 'bg-blue-500/20', icon: BookOpen },
  'alert': { color: 'text-orange-400', bg: 'bg-orange-500/20', icon: Zap },
  'technique': { color: 'text-cyan-400', bg: 'bg-cyan-500/20', icon: Tag },
  'threat-actor': { color: 'text-pink-400', bg: 'bg-pink-500/20', icon: Brain }
}

export default function MnemosyneRAG() {
  const [documents, setDocuments] = useState<Document[]>(DEMO_DOCUMENTS)
  const [query, setQuery] = useState('')
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [ragResponse, setRagResponse] = useState<RAGResponse | null>(null)
  const [isSearching, setIsSearching] = useState(false)
  const [isRAGMode, setIsRAGMode] = useState(true)
  const [vocabulary, setVocabulary] = useState<string[]>([])
  const [selectedDocument, setSelectedDocument] = useState<Document | null>(null)
  const [showAddDocument, setShowAddDocument] = useState(false)
  const [newDocument, setNewDocument] = useState({
    title: '',
    content: '',
    type: 'note' as Document['type'],
    tags: ''
  })
  const [expandedSources, setExpandedSources] = useState<string[]>([])

  // Build vocabulary and embeddings on mount
  useEffect(() => {
    const texts = documents.map(d => d.content + ' ' + d.title)
    const vocab = buildVocabulary(texts)
    setVocabulary(vocab)

    // Create embeddings for all documents
    setDocuments(docs => docs.map(doc => ({
      ...doc,
      embedding: createEmbedding(doc.content + ' ' + doc.title, vocab)
    })))
  }, [])

  // Highlight matching terms
  const highlightTerms = (text: string, terms: string[]): string[] => {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim())
    const highlights: string[] = []

    sentences.forEach(sentence => {
      const lowerSentence = sentence.toLowerCase()
      if (terms.some(term => lowerSentence.includes(term.toLowerCase()))) {
        highlights.push(sentence.trim())
      }
    })

    return highlights.slice(0, 3)
  }

  // Vector search
  const performSearch = useCallback(async () => {
    if (!query.trim()) return

    setIsSearching(true)

    // Simulate async processing
    await new Promise(resolve => setTimeout(resolve, 500))

    const queryTerms = query.toLowerCase().split(/\W+/).filter(w => w.length > 2)
    const queryEmbedding = createEmbedding(query, vocabulary)

    const results: SearchResult[] = documents
      .filter(doc => doc.embedding)
      .map(doc => ({
        document: doc,
        similarity: cosineSimilarity(queryEmbedding, doc.embedding!),
        highlights: highlightTerms(doc.content, queryTerms)
      }))
      .filter(r => r.similarity > 0.05)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, 10)

    setSearchResults(results)

    // Generate RAG response if enabled
    if (isRAGMode && results.length > 0) {
      await generateRAGResponse(query, results)
    }

    setIsSearching(false)
  }, [query, vocabulary, documents, isRAGMode])

  // Simulated RAG response generation
  const generateRAGResponse = async (userQuery: string, results: SearchResult[]) => {
    // Simulate LLM processing
    await new Promise(resolve => setTimeout(resolve, 1000))

    const topDocs = results.slice(0, 3)
    const queryLower = userQuery.toLowerCase()

    // Generate contextual answer based on query and documents
    let answer = ''
    const reasoning: string[] = []

    if (queryLower.includes('apt29') || queryLower.includes('sunburst') || queryLower.includes('solarwinds')) {
      answer = 'Based on the indexed intelligence, APT29 (Cozy Bear) executed a sophisticated supply chain attack through the SolarWinds Orion platform. The SUNBURST malware was distributed via trojanized software updates, exploiting trusted update mechanisms. The campaign targeted government agencies and technology companies. Persistence was achieved through scheduled tasks and registry modifications.'
      reasoning.push('Matched query to APT29/SUNBURST analysis report')
      reasoning.push('Cross-referenced with MITRE ATT&CK techniques')
      reasoning.push('Correlated with IOC feed data')
    } else if (queryLower.includes('cobalt') || queryLower.includes('c2') || queryLower.includes('beacon')) {
      answer = 'Cobalt Strike beacon activity was detected communicating with C2 infrastructure. The beacon used HTTPS with malleable C2 profiles for evasion. Process injection was observed in system processes (explorer.exe, svchost.exe). Memory forensics revealed characteristic Cobalt Strike shellcode patterns. Recommend network isolation and memory analysis.'
      reasoning.push('Identified Cobalt Strike beacon patterns')
      reasoning.push('Analyzed C2 communication indicators')
      reasoning.push('Correlated with process injection techniques')
    } else if (queryLower.includes('powershell') || queryLower.includes('t1059')) {
      answer = 'PowerShell abuse (T1059.001) is commonly used for execution by threat actors. Detection should focus on encoded commands, execution policy bypass attempts, remote script downloads, and fileless execution patterns. Enable Script Block Logging and monitor for suspicious command-line parameters.'
      reasoning.push('Mapped to MITRE ATT&CK T1059.001')
      reasoning.push('Retrieved detection guidance')
      reasoning.push('Synthesized mitigation recommendations')
    } else if (queryLower.includes('fin7') || queryLower.includes('financial')) {
      answer = 'FIN7 is a sophisticated threat group targeting financial and retail sectors. Their TTPs include spear-phishing with malicious documents, use of Carbanak and Cobalt Strike for post-exploitation, and abuse of legitimate tools (PowerShell, WMI) for lateral movement. They are known for advanced social engineering techniques.'
      reasoning.push('Retrieved FIN7 threat actor profile')
      reasoning.push('Correlated known TTPs')
      reasoning.push('Cross-referenced with tooling analysis')
    } else {
      // Generic response based on top results
      const topTags = topDocs.flatMap(d => d.document.tags).slice(0, 5)
      answer = `Based on semantic search across ${documents.length} indexed documents, the most relevant findings relate to: ${topTags.join(', ')}. ${topDocs[0]?.highlights[0] || 'Review the source documents for detailed analysis.'}`
      reasoning.push(`Performed vector similarity search (top match: ${(topDocs[0]?.similarity * 100).toFixed(1)}%)`)
      reasoning.push(`Analyzed ${topDocs.length} relevant documents`)
      reasoning.push('Generated synthesis from matched content')
    }

    const avgConfidence = topDocs.reduce((sum, r) => sum + (r.document.confidence || 80), 0) / topDocs.length

    setRagResponse({
      answer,
      sources: topDocs.map(r => r.document),
      confidence: Math.min(avgConfidence * (topDocs[0]?.similarity || 0.5) * 1.5, 100),
      reasoning
    })
  }

  // Add new document
  const addDocument = () => {
    if (!newDocument.title || !newDocument.content) return

    const doc: Document = {
      id: `doc-${Date.now()}`,
      title: newDocument.title,
      content: newDocument.content,
      type: newDocument.type,
      tags: newDocument.tags.split(',').map(t => t.trim()).filter(Boolean),
      timestamp: Date.now(),
      confidence: 100,
      source: 'Manual Entry'
    }

    // Create embedding
    doc.embedding = createEmbedding(doc.content + ' ' + doc.title, vocabulary)

    setDocuments([doc, ...documents])
    setNewDocument({ title: '', content: '', type: 'note', tags: '' })
    setShowAddDocument(false)
  }

  // Delete document
  const deleteDocument = (id: string) => {
    setDocuments(documents.filter(d => d.id !== id))
    if (selectedDocument?.id === id) setSelectedDocument(null)
  }

  return (
    <div className="h-full flex bg-null-bg">
      {/* Left Panel - Document Index */}
      <div className="w-80 border-r border-null-border flex flex-col">
        <div className="p-4 border-b border-null-border">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Database className="w-5 h-5 text-purple-400" />
              <span className="font-display text-null-text">MNEMOSYNE</span>
            </div>
            <button
              onClick={() => setShowAddDocument(true)}
              className="p-1.5 rounded bg-purple-500/20 text-purple-400 hover:bg-purple-500/30"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>
          <p className="text-xs text-null-muted">
            Local-first RAG • {documents.length} documents indexed
          </p>
        </div>

        {/* Document List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {documents.map(doc => {
            const config = TYPE_CONFIG[doc.type]
            const Icon = config.icon
            return (
              <button
                key={doc.id}
                onClick={() => setSelectedDocument(doc)}
                className={`w-full p-3 rounded-lg text-left transition-all ${
                  selectedDocument?.id === doc.id
                    ? 'bg-purple-500/20 border border-purple-500/30'
                    : 'bg-null-surface/50 hover:bg-null-surface border border-transparent'
                }`}
              >
                <div className="flex items-start gap-2">
                  <Icon className={`w-4 h-4 mt-0.5 ${config.color}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-null-text truncate">{doc.title}</div>
                    <div className="text-xs text-null-muted truncate mt-1">
                      {doc.content.slice(0, 60)}...
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] ${config.bg} ${config.color}`}>
                        {doc.type}
                      </span>
                      <span className="text-[10px] text-null-muted">
                        {new Date(doc.timestamp).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Center Panel - Search & RAG */}
      <div className="flex-1 flex flex-col">
        {/* Search Header */}
        <div className="p-4 border-b border-null-border bg-null-surface/30">
          <div className="flex items-center gap-3 mb-3">
            <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-lg bg-null-bg border border-null-border">
              <Search className="w-4 h-4 text-null-muted" />
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && performSearch()}
                placeholder="Ask a question or search documents..."
                className="flex-1 bg-transparent text-null-text placeholder:text-null-muted outline-none"
              />
              {isSearching && <RefreshCw className="w-4 h-4 text-purple-400 animate-spin" />}
            </div>
            <button
              onClick={performSearch}
              disabled={isSearching || !query.trim()}
              className="px-4 py-2 rounded-lg bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50 flex items-center gap-2"
            >
              <Sparkles className="w-4 h-4" />
              Search
            </button>
          </div>

          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={isRAGMode}
                onChange={e => setIsRAGMode(e.target.checked)}
                className="rounded border-null-border bg-null-bg"
              />
              <span className="text-sm text-null-muted">Enable RAG synthesis</span>
            </label>
            <span className="text-xs text-null-muted">
              Vocab size: {vocabulary.length} terms
            </span>
          </div>
        </div>

        {/* Results Area */}
        <div className="flex-1 overflow-y-auto p-4">
          <AnimatePresence mode="wait">
            {ragResponse && isRAGMode ? (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="mb-6"
              >
                {/* RAG Response Card */}
                <div className="p-4 rounded-lg bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 mb-4">
                  <div className="flex items-start gap-3 mb-3">
                    <div className="p-2 rounded-lg bg-purple-500/20">
                      <Brain className="w-5 h-5 text-purple-400" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-null-text">AI-Generated Answer</div>
                      <div className="text-xs text-null-muted">
                        Confidence: {ragResponse.confidence.toFixed(0)}% • {ragResponse.sources.length} sources
                      </div>
                    </div>
                  </div>

                  <p className="text-sm text-null-text leading-relaxed mb-4">
                    {ragResponse.answer}
                  </p>

                  {/* Reasoning Steps */}
                  <div className="mb-4">
                    <div className="text-xs text-null-muted mb-2">Reasoning:</div>
                    <div className="space-y-1">
                      {ragResponse.reasoning.map((step, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          <span className="w-4 h-4 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center text-[10px]">
                            {i + 1}
                          </span>
                          <span className="text-null-muted">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Sources */}
                  <div>
                    <div className="text-xs text-null-muted mb-2">Sources:</div>
                    <div className="space-y-2">
                      {ragResponse.sources.map(source => {
                        const config = TYPE_CONFIG[source.type]
                        const Icon = config.icon
                        const isExpanded = expandedSources.includes(source.id)

                        return (
                          <div key={source.id} className="rounded bg-null-bg/50 border border-null-border">
                            <button
                              onClick={() => setExpandedSources(prev =>
                                isExpanded ? prev.filter(id => id !== source.id) : [...prev, source.id]
                              )}
                              className="w-full p-2 flex items-center gap-2 text-left"
                            >
                              {isExpanded ? (
                                <ChevronDown className="w-3 h-3 text-null-muted" />
                              ) : (
                                <ChevronRight className="w-3 h-3 text-null-muted" />
                              )}
                              <Icon className={`w-3 h-3 ${config.color}`} />
                              <span className="text-xs text-null-text truncate flex-1">{source.title}</span>
                              <span className={`px-1 py-0.5 rounded text-[10px] ${config.bg} ${config.color}`}>
                                {source.type}
                              </span>
                            </button>

                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: 'auto', opacity: 1 }}
                                  exit={{ height: 0, opacity: 0 }}
                                  className="overflow-hidden"
                                >
                                  <div className="p-2 pt-0 text-xs text-null-muted">
                                    {source.content.slice(0, 200)}...
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              </motion.div>
            ) : null}
          </AnimatePresence>

          {/* Search Results */}
          {searchResults.length > 0 && (
            <div>
              <div className="text-xs text-null-muted mb-3">
                {searchResults.length} results found
              </div>
              <div className="space-y-3">
                {searchResults.map(result => {
                  const config = TYPE_CONFIG[result.document.type]
                  const Icon = config.icon

                  return (
                    <motion.div
                      key={result.document.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="p-4 rounded-lg bg-null-surface/50 border border-null-border hover:border-purple-500/30 transition-colors cursor-pointer"
                      onClick={() => setSelectedDocument(result.document)}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-4 h-4 ${config.color}`} />
                          <span className="text-sm font-medium text-null-text">
                            {result.document.title}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${config.bg} ${config.color}`}>
                            {result.document.type}
                          </span>
                          <span className="text-xs text-purple-400 font-mono">
                            {(result.similarity * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>

                      {result.highlights.length > 0 && (
                        <div className="mb-2">
                          {result.highlights.map((highlight, i) => (
                            <p key={i} className="text-xs text-null-muted italic">
                              "...{highlight}..."
                            </p>
                          ))}
                        </div>
                      )}

                      <div className="flex items-center gap-2 flex-wrap">
                        {result.document.tags.map(tag => (
                          <span key={tag} className="px-1.5 py-0.5 rounded bg-null-border/50 text-[10px] text-null-muted">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </motion.div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Empty State */}
          {!isSearching && searchResults.length === 0 && !ragResponse && (
            <div className="flex flex-col items-center justify-center h-64 text-null-muted">
              <Search className="w-12 h-12 mb-4 opacity-50" />
              <p className="text-sm">Enter a query to search the knowledge base</p>
              <p className="text-xs mt-1">Try: "APT29 attack patterns" or "PowerShell detection"</p>
            </div>
          )}
        </div>
      </div>

      {/* Right Panel - Document Detail */}
      <AnimatePresence>
        {selectedDocument && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 400, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            className="border-l border-null-border flex flex-col overflow-hidden"
          >
            <div className="p-4 border-b border-null-border flex items-center justify-between">
              <span className="font-display text-null-text">Document Details</span>
              <button
                onClick={() => setSelectedDocument(null)}
                className="text-null-muted hover:text-null-text"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4">
              <div className="mb-4">
                <h3 className="text-lg font-medium text-null-text mb-2">
                  {selectedDocument.title}
                </h3>

                <div className="flex items-center gap-2 flex-wrap mb-4">
                  {(() => {
                    const config = TYPE_CONFIG[selectedDocument.type]
                    return (
                      <span className={`px-2 py-1 rounded text-xs ${config.bg} ${config.color}`}>
                        {selectedDocument.type}
                      </span>
                    )
                  })()}
                  <span className="text-xs text-null-muted flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {new Date(selectedDocument.timestamp).toLocaleDateString()}
                  </span>
                  {selectedDocument.source && (
                    <span className="text-xs text-null-muted flex items-center gap-1">
                      <Link2 className="w-3 h-3" />
                      {selectedDocument.source}
                    </span>
                  )}
                </div>

                {selectedDocument.confidence && (
                  <div className="mb-4">
                    <div className="text-xs text-null-muted mb-1">Confidence</div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-null-border rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-purple-500 to-pink-500"
                          style={{ width: `${selectedDocument.confidence}%` }}
                        />
                      </div>
                      <span className="text-xs text-null-text font-mono">
                        {selectedDocument.confidence}%
                      </span>
                    </div>
                  </div>
                )}
              </div>

              <div className="mb-4">
                <div className="text-xs text-null-muted mb-2">Content</div>
                <p className="text-sm text-null-text leading-relaxed whitespace-pre-wrap">
                  {selectedDocument.content}
                </p>
              </div>

              <div className="mb-4">
                <div className="text-xs text-null-muted mb-2">Tags</div>
                <div className="flex items-center gap-2 flex-wrap">
                  {selectedDocument.tags.map(tag => (
                    <span key={tag} className="px-2 py-1 rounded bg-null-surface text-xs text-null-text">
                      #{tag}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex gap-2">
                <button className="flex-1 px-3 py-2 rounded bg-null-surface text-null-text text-xs hover:bg-null-border flex items-center justify-center gap-2">
                  <Download className="w-3 h-3" />
                  Export
                </button>
                <button
                  onClick={() => deleteDocument(selectedDocument.id)}
                  className="px-3 py-2 rounded bg-red-500/20 text-red-400 text-xs hover:bg-red-500/30"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Add Document Modal */}
      <AnimatePresence>
        {showAddDocument && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 flex items-center justify-center z-50"
            onClick={() => setShowAddDocument(false)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="w-[500px] bg-null-surface rounded-lg border border-null-border p-6"
              onClick={e => e.stopPropagation()}
            >
              <h3 className="text-lg font-display text-null-text mb-4">Add Document</h3>

              <div className="space-y-4">
                <div>
                  <label className="block text-xs text-null-muted mb-1">Title</label>
                  <input
                    type="text"
                    value={newDocument.title}
                    onChange={e => setNewDocument({ ...newDocument, title: e.target.value })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text"
                    placeholder="Document title..."
                  />
                </div>

                <div>
                  <label className="block text-xs text-null-muted mb-1">Type</label>
                  <select
                    value={newDocument.type}
                    onChange={e => setNewDocument({ ...newDocument, type: e.target.value as Document['type'] })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text"
                  >
                    <option value="note">Note</option>
                    <option value="report">Report</option>
                    <option value="ioc">IOC</option>
                    <option value="alert">Alert</option>
                    <option value="technique">Technique</option>
                    <option value="threat-actor">Threat Actor</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs text-null-muted mb-1">Content</label>
                  <textarea
                    value={newDocument.content}
                    onChange={e => setNewDocument({ ...newDocument, content: e.target.value })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text h-32"
                    placeholder="Document content..."
                  />
                </div>

                <div>
                  <label className="block text-xs text-null-muted mb-1">Tags (comma-separated)</label>
                  <input
                    type="text"
                    value={newDocument.tags}
                    onChange={e => setNewDocument({ ...newDocument, tags: e.target.value })}
                    className="w-full px-3 py-2 rounded bg-null-bg border border-null-border text-null-text"
                    placeholder="tag1, tag2, tag3"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-6">
                <button
                  onClick={() => setShowAddDocument(false)}
                  className="px-4 py-2 rounded text-null-muted hover:text-null-text"
                >
                  Cancel
                </button>
                <button
                  onClick={addDocument}
                  disabled={!newDocument.title || !newDocument.content}
                  className="px-4 py-2 rounded bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50"
                >
                  Add Document
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
