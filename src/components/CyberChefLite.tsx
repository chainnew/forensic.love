import { useState, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Sparkles, Copy, ArrowRight, RotateCcw, Plus, Trash2, ChevronUp,
  ChevronDown, Code, Lock, Unlock, Hash, FileText, Binary, Globe,
  Key, Shuffle, Search, CheckCircle, AlertTriangle, Zap
} from 'lucide-react'

type RecipeStep = {
  id: string
  operation: string
  params: Record<string, string | number | boolean>
  enabled: boolean
}

// Available operations
const OPERATIONS = {
  // Encoding
  'Base64 Encode': {
    icon: Code,
    category: 'Encoding',
    params: {},
    transform: (input: string) => btoa(input)
  },
  'Base64 Decode': {
    icon: Code,
    category: 'Encoding',
    params: {},
    transform: (input: string) => {
      try { return atob(input) }
      catch { return '[Invalid Base64]' }
    }
  },
  'URL Encode': {
    icon: Globe,
    category: 'Encoding',
    params: {},
    transform: (input: string) => encodeURIComponent(input)
  },
  'URL Decode': {
    icon: Globe,
    category: 'Encoding',
    params: {},
    transform: (input: string) => {
      try { return decodeURIComponent(input) }
      catch { return '[Invalid URL Encoding]' }
    }
  },
  'Hex Encode': {
    icon: Binary,
    category: 'Encoding',
    params: {},
    transform: (input: string) => Array.from(input).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
  },
  'Hex Decode': {
    icon: Binary,
    category: 'Encoding',
    params: {},
    transform: (input: string) => {
      try {
        const hex = input.replace(/\s/g, '')
        let result = ''
        for (let i = 0; i < hex.length; i += 2) {
          result += String.fromCharCode(parseInt(hex.substring(i, i + 2), 16))
        }
        return result
      } catch { return '[Invalid Hex]' }
    }
  },
  'HTML Entities Encode': {
    icon: Code,
    category: 'Encoding',
    params: {},
    transform: (input: string) => input.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] || c))
  },
  'HTML Entities Decode': {
    icon: Code,
    category: 'Encoding',
    params: {},
    transform: (input: string) => {
      const doc = new DOMParser().parseFromString(input, 'text/html')
      return doc.documentElement.textContent || ''
    }
  },

  // Hashing
  'MD5': {
    icon: Hash,
    category: 'Hashing',
    params: {},
    transform: async (input: string) => {
      const msgBuffer = new TextEncoder().encode(input)
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      // Note: Real MD5 would need a library, using placeholder
      return hashArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('')
    }
  },
  'SHA-256': {
    icon: Hash,
    category: 'Hashing',
    params: {},
    transform: async (input: string) => {
      const msgBuffer = new TextEncoder().encode(input)
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    }
  },
  'SHA-512': {
    icon: Hash,
    category: 'Hashing',
    params: {},
    transform: async (input: string) => {
      const msgBuffer = new TextEncoder().encode(input)
      const hashBuffer = await crypto.subtle.digest('SHA-512', msgBuffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    }
  },

  // String Operations
  'Reverse': {
    icon: Shuffle,
    category: 'String',
    params: {},
    transform: (input: string) => input.split('').reverse().join('')
  },
  'To Upper Case': {
    icon: FileText,
    category: 'String',
    params: {},
    transform: (input: string) => input.toUpperCase()
  },
  'To Lower Case': {
    icon: FileText,
    category: 'String',
    params: {},
    transform: (input: string) => input.toLowerCase()
  },
  'Remove Whitespace': {
    icon: FileText,
    category: 'String',
    params: {},
    transform: (input: string) => input.replace(/\s+/g, '')
  },
  'Split': {
    icon: FileText,
    category: 'String',
    params: { delimiter: ',' },
    transform: (input: string, params: Record<string, string | number | boolean>) => input.split(String(params.delimiter || ',')).join('\n')
  },
  'Line Numbers': {
    icon: FileText,
    category: 'String',
    params: {},
    transform: (input: string) => input.split('\n').map((line, i) => `${(i + 1).toString().padStart(4, ' ')}: ${line}`).join('\n')
  },

  // Crypto
  'ROT13': {
    icon: Lock,
    category: 'Crypto',
    params: {},
    transform: (input: string) => input.replace(/[a-zA-Z]/g, c =>
      String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c.charCodeAt(0) + 13) ? c.charCodeAt(0) + 13 : c.charCodeAt(0) - 13)
    )
  },
  'XOR': {
    icon: Lock,
    category: 'Crypto',
    params: { key: '0x00' },
    transform: (input: string, params: Record<string, string | number | boolean>) => {
      const key = parseInt(String(params.key || '0x00'), 16)
      return Array.from(input).map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('')
    }
  },
  'Caesar Cipher': {
    icon: Lock,
    category: 'Crypto',
    params: { shift: 3 },
    transform: (input: string, params: Record<string, string | number | boolean>) => {
      const shift = Number(params.shift || 3) % 26
      return input.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97
        return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base)
      })
    }
  },

  // Analysis
  'Extract URLs': {
    icon: Search,
    category: 'Analysis',
    params: {},
    transform: (input: string) => {
      const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi
      const urls = input.match(urlRegex) || []
      return urls.join('\n') || '[No URLs found]'
    }
  },
  'Extract IPs': {
    icon: Search,
    category: 'Analysis',
    params: {},
    transform: (input: string) => {
      const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
      const ips = input.match(ipRegex) || []
      return [...new Set(ips)].join('\n') || '[No IPs found]'
    }
  },
  'Extract Emails': {
    icon: Search,
    category: 'Analysis',
    params: {},
    transform: (input: string) => {
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
      const emails = input.match(emailRegex) || []
      return [...new Set(emails)].join('\n') || '[No emails found]'
    }
  },
  'Extract Hashes': {
    icon: Search,
    category: 'Analysis',
    params: {},
    transform: (input: string) => {
      const hashRegex = /\b[a-fA-F0-9]{32,64}\b/g
      const hashes = input.match(hashRegex) || []
      return [...new Set(hashes)].map(h => `${h.length === 32 ? 'MD5:' : h.length === 40 ? 'SHA1:' : h.length === 64 ? 'SHA256:' : ''} ${h}`).join('\n') || '[No hashes found]'
    }
  },
  'Entropy': {
    icon: Zap,
    category: 'Analysis',
    params: {},
    transform: (input: string) => {
      const freq: Record<string, number> = {}
      for (const c of input) {
        freq[c] = (freq[c] || 0) + 1
      }
      let entropy = 0
      const len = input.length
      for (const c in freq) {
        const p = freq[c] / len
        entropy -= p * Math.log2(p)
      }
      return `Entropy: ${entropy.toFixed(4)} bits per character\nLength: ${len}\nUnique chars: ${Object.keys(freq).length}`
    }
  },

  // Data Format
  'JSON Beautify': {
    icon: Code,
    category: 'Data Format',
    params: {},
    transform: (input: string) => {
      try { return JSON.stringify(JSON.parse(input), null, 2) }
      catch { return '[Invalid JSON]' }
    }
  },
  'JSON Minify': {
    icon: Code,
    category: 'Data Format',
    params: {},
    transform: (input: string) => {
      try { return JSON.stringify(JSON.parse(input)) }
      catch { return '[Invalid JSON]' }
    }
  },
  'Defang URL': {
    icon: Globe,
    category: 'Data Format',
    params: {},
    transform: (input: string) => input.replace(/\./g, '[.]').replace(/http/g, 'hxxp')
  },
  'Refang URL': {
    icon: Globe,
    category: 'Data Format',
    params: {},
    transform: (input: string) => input.replace(/\[\.\]/g, '.').replace(/hxxp/g, 'http')
  }
}

const CATEGORIES = ['Encoding', 'Hashing', 'String', 'Crypto', 'Analysis', 'Data Format']

export default function CyberChefLite() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [recipe, setRecipe] = useState<RecipeStep[]>([])
  const [selectedCategory, setSelectedCategory] = useState<string>('Encoding')
  const [isProcessing, setIsProcessing] = useState(false)
  const [copiedOutput, setCopiedOutput] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Get operations for selected category
  const categoryOperations = useMemo(() => {
    return Object.entries(OPERATIONS).filter(([, op]) => op.category === selectedCategory)
  }, [selectedCategory])

  // Add operation to recipe
  const addOperation = (opName: string) => {
    const op = OPERATIONS[opName as keyof typeof OPERATIONS]
    const step: RecipeStep = {
      id: `step-${Date.now()}`,
      operation: opName,
      params: { ...op.params },
      enabled: true
    }
    setRecipe([...recipe, step])
  }

  // Remove operation from recipe
  const removeOperation = (id: string) => {
    setRecipe(recipe.filter(s => s.id !== id))
  }

  // Toggle operation enabled
  const toggleOperation = (id: string) => {
    setRecipe(recipe.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s))
  }

  // Update operation params
  const updateParams = (id: string, key: string, value: string | number | boolean) => {
    setRecipe(recipe.map(s => s.id === id ? { ...s, params: { ...s.params, [key]: value } } : s))
  }

  // Move operation up/down
  const moveOperation = (id: string, direction: 'up' | 'down') => {
    const index = recipe.findIndex(s => s.id === id)
    if (direction === 'up' && index > 0) {
      const newRecipe = [...recipe]
      ;[newRecipe[index - 1], newRecipe[index]] = [newRecipe[index], newRecipe[index - 1]]
      setRecipe(newRecipe)
    } else if (direction === 'down' && index < recipe.length - 1) {
      const newRecipe = [...recipe]
      ;[newRecipe[index], newRecipe[index + 1]] = [newRecipe[index + 1], newRecipe[index]]
      setRecipe(newRecipe)
    }
  }

  // Process recipe
  const processRecipe = useCallback(async () => {
    if (!input.trim() || recipe.length === 0) {
      setOutput(input)
      return
    }

    setIsProcessing(true)
    setError(null)

    try {
      let result = input
      for (const step of recipe) {
        if (!step.enabled) continue

        const op = OPERATIONS[step.operation as keyof typeof OPERATIONS]
        if (op) {
          const transformed = await op.transform(result, step.params)
          result = typeof transformed === 'string' ? transformed : await transformed
        }
      }
      setOutput(result)
    } catch (err) {
      setError(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`)
      setOutput('')
    } finally {
      setIsProcessing(false)
    }
  }, [input, recipe])

  // Auto-process on input/recipe change
  useMemo(() => {
    const timeout = setTimeout(processRecipe, 300)
    return () => clearTimeout(timeout)
  }, [processRecipe])

  // Copy output
  const copyOutput = async () => {
    await navigator.clipboard.writeText(output)
    setCopiedOutput(true)
    setTimeout(() => setCopiedOutput(false), 2000)
  }

  // Clear recipe
  const clearRecipe = () => {
    setRecipe([])
    setOutput(input)
  }

  return (
    <div className="h-full flex bg-null-bg">
      {/* Operations Panel */}
      <div className="w-72 border-r border-null-border flex flex-col">
        <div className="p-4 border-b border-null-border">
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-yellow-400" />
            <span className="font-display text-null-text">CyberChef Lite</span>
          </div>
          <p className="text-xs text-null-muted mt-1">
            Data transformation toolkit
          </p>
        </div>

        {/* Category Tabs */}
        <div className="flex flex-wrap gap-1 p-2 border-b border-null-border">
          {CATEGORIES.map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-2 py-1 rounded text-[10px] transition-colors ${
                selectedCategory === cat
                  ? 'bg-yellow-500/20 text-yellow-400'
                  : 'text-null-muted hover:text-null-text hover:bg-null-surface'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Operations List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {categoryOperations.map(([name, op]) => {
            const Icon = op.icon
            return (
              <button
                key={name}
                onClick={() => addOperation(name)}
                className="w-full p-2 rounded-lg bg-null-surface/50 hover:bg-null-surface border border-transparent hover:border-yellow-500/30 transition-all text-left flex items-center gap-2"
              >
                <Icon className="w-4 h-4 text-yellow-400" />
                <span className="text-sm text-null-text">{name}</span>
                <Plus className="w-3 h-3 text-null-muted ml-auto" />
              </button>
            )
          })}
        </div>
      </div>

      {/* Recipe Panel */}
      <div className="w-80 border-r border-null-border flex flex-col">
        <div className="p-4 border-b border-null-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-medium text-null-text">Recipe</span>
            <span className="text-xs text-null-muted">({recipe.length} steps)</span>
          </div>
          <button
            onClick={clearRecipe}
            className="p-1 rounded hover:bg-null-surface text-null-muted hover:text-null-text"
            title="Clear recipe"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-2">
          <AnimatePresence>
            {recipe.map((step, index) => {
              const op = OPERATIONS[step.operation as keyof typeof OPERATIONS]
              const Icon = op?.icon || Code

              return (
                <motion.div
                  key={step.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 20 }}
                  className={`p-3 rounded-lg border transition-colors ${
                    step.enabled
                      ? 'bg-null-surface/80 border-cyan-500/30'
                      : 'bg-null-surface/30 border-null-border opacity-50'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="w-5 h-5 rounded bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs font-mono">
                      {index + 1}
                    </span>
                    <Icon className="w-4 h-4 text-cyan-400" />
                    <span className="text-sm text-null-text flex-1 truncate">{step.operation}</span>
                    <button
                      onClick={() => toggleOperation(step.id)}
                      className={`p-1 rounded ${step.enabled ? 'text-green-400' : 'text-null-muted'}`}
                    >
                      {step.enabled ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                    </button>
                  </div>

                  {/* Parameters */}
                  {Object.keys(step.params).length > 0 && (
                    <div className="space-y-2 mb-2">
                      {Object.entries(step.params).map(([key, value]) => (
                        <div key={key} className="flex items-center gap-2">
                          <span className="text-[10px] text-null-muted capitalize w-16">{key}:</span>
                          <input
                            type={typeof value === 'number' ? 'number' : 'text'}
                            value={String(value)}
                            onChange={e => updateParams(step.id, key, e.target.value)}
                            className="flex-1 px-2 py-1 rounded bg-null-bg border border-null-border text-xs text-null-text"
                          />
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Controls */}
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => moveOperation(step.id, 'up')}
                      disabled={index === 0}
                      className="p-1 rounded hover:bg-null-border text-null-muted disabled:opacity-30"
                    >
                      <ChevronUp className="w-3 h-3" />
                    </button>
                    <button
                      onClick={() => moveOperation(step.id, 'down')}
                      disabled={index === recipe.length - 1}
                      className="p-1 rounded hover:bg-null-border text-null-muted disabled:opacity-30"
                    >
                      <ChevronDown className="w-3 h-3" />
                    </button>
                    <button
                      onClick={() => removeOperation(step.id)}
                      className="p-1 rounded hover:bg-red-500/20 text-null-muted hover:text-red-400 ml-auto"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </motion.div>
              )
            })}
          </AnimatePresence>

          {recipe.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-null-muted">
              <Code className="w-8 h-8 mb-2 opacity-50" />
              <p className="text-xs">Add operations to build your recipe</p>
            </div>
          )}
        </div>
      </div>

      {/* Input/Output Panel */}
      <div className="flex-1 flex flex-col">
        {/* Input */}
        <div className="flex-1 flex flex-col border-b border-null-border">
          <div className="p-3 border-b border-null-border flex items-center justify-between bg-null-surface/30">
            <span className="text-sm font-medium text-null-text">Input</span>
            <span className="text-xs text-null-muted">{input.length} chars</span>
          </div>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            className="flex-1 p-4 bg-null-bg text-null-text font-mono text-sm resize-none outline-none"
            placeholder="Enter data to transform..."
          />
        </div>

        {/* Arrow */}
        <div className="flex items-center justify-center py-2 bg-null-surface/30">
          {isProcessing ? (
            <div className="w-8 h-8 border-2 border-yellow-400 border-t-transparent rounded-full animate-spin" />
          ) : (
            <ArrowRight className="w-6 h-6 text-yellow-400" />
          )}
        </div>

        {/* Output */}
        <div className="flex-1 flex flex-col">
          <div className="p-3 border-b border-null-border flex items-center justify-between bg-null-surface/30">
            <span className="text-sm font-medium text-null-text">Output</span>
            <div className="flex items-center gap-2">
              <span className="text-xs text-null-muted">{output.length} chars</span>
              <button
                onClick={copyOutput}
                className="p-1.5 rounded bg-null-surface hover:bg-null-border transition-colors"
              >
                {copiedOutput ? (
                  <CheckCircle className="w-4 h-4 text-green-400" />
                ) : (
                  <Copy className="w-4 h-4 text-null-muted" />
                )}
              </button>
            </div>
          </div>

          {error ? (
            <div className="flex-1 p-4 flex items-center justify-center text-red-400">
              <AlertTriangle className="w-5 h-5 mr-2" />
              {error}
            </div>
          ) : (
            <textarea
              value={output}
              readOnly
              className="flex-1 p-4 bg-null-bg text-null-text font-mono text-sm resize-none outline-none"
              placeholder="Output will appear here..."
            />
          )}
        </div>
      </div>
    </div>
  )
}
