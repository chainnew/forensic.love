import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Users, Globe, MessageSquare, Share2, Lock, Unlock, Eye, Edit3,
  UserPlus, Settings, Bell, Clock, CheckCircle, AlertTriangle,
  Zap, Activity, Send, AtSign, Hash, Plus, X, MoreVertical
} from 'lucide-react'

// User presence types
interface User {
  id: string
  name: string
  avatar?: string
  color: string
  role: 'admin' | 'analyst' | 'viewer'
  status: 'online' | 'away' | 'busy'
  lastSeen: number
  cursor?: { x: number; y: number; page: string }
}

// Collaboration room
interface Room {
  id: string
  name: string
  description: string
  isPrivate: boolean
  tlpLevel: 'white' | 'green' | 'amber' | 'red'
  members: string[]
  activeUsers: number
  lastActivity: number
}

// Chat message
interface Message {
  id: string
  userId: string
  content: string
  timestamp: number
  mentions?: string[]
  attachments?: { type: string; name: string; url: string }[]
  reactions?: { emoji: string; users: string[] }[]
}

// Shared annotation/comment on evidence
interface Annotation {
  id: string
  userId: string
  targetType: 'ioc' | 'event' | 'report' | 'graph_node'
  targetId: string
  content: string
  timestamp: number
  resolved: boolean
}

// Activity feed item
interface ActivityItem {
  id: string
  userId: string
  action: 'joined' | 'left' | 'commented' | 'updated' | 'shared' | 'flagged'
  target: string
  timestamp: number
}

// Demo data
const DEMO_USERS: User[] = [
  { id: 'u1', name: 'Alice Chen', color: '#22d3ee', role: 'admin', status: 'online', lastSeen: Date.now() },
  { id: 'u2', name: 'Bob Martinez', color: '#a855f7', role: 'analyst', status: 'online', lastSeen: Date.now() - 30000 },
  { id: 'u3', name: 'Carol Singh', color: '#f97316', role: 'analyst', status: 'away', lastSeen: Date.now() - 300000 },
  { id: 'u4', name: 'David Kim', color: '#22c55e', role: 'viewer', status: 'busy', lastSeen: Date.now() - 60000 },
]

const DEMO_ROOMS: Room[] = [
  { id: 'r1', name: 'APT29 Investigation', description: 'Active investigation into SolarWinds compromise', isPrivate: false, tlpLevel: 'amber', members: ['u1', 'u2', 'u3', 'u4'], activeUsers: 3, lastActivity: Date.now() - 120000 },
  { id: 'r2', name: 'Ransomware Response', description: 'Incident response for LockBit attack', isPrivate: true, tlpLevel: 'red', members: ['u1', 'u2'], activeUsers: 2, lastActivity: Date.now() - 3600000 },
  { id: 'r3', name: 'Threat Intel Sharing', description: 'General threat intel discussion', isPrivate: false, tlpLevel: 'green', members: ['u1', 'u2', 'u3', 'u4'], activeUsers: 1, lastActivity: Date.now() - 7200000 },
]

const DEMO_MESSAGES: Message[] = [
  { id: 'm1', userId: 'u1', content: 'Found additional C2 domains related to the SUNBURST malware. Updating the IOC list.', timestamp: Date.now() - 600000 },
  { id: 'm2', userId: 'u2', content: '@Alice Chen Great find! Can you share the STIX bundle?', timestamp: Date.now() - 540000, mentions: ['u1'] },
  { id: 'm3', userId: 'u1', content: 'Uploaded to the shared artifacts. TLP:AMBER applies.', timestamp: Date.now() - 480000, attachments: [{ type: 'stix', name: 'sunburst_iocs.json', url: '#' }] },
  { id: 'm4', userId: 'u3', content: 'I\'ve correlated these with our internal logs. Found 3 potential victims.', timestamp: Date.now() - 300000 },
  { id: 'm5', userId: 'u2', content: 'Escalating to IR team. Marking this as critical.', timestamp: Date.now() - 120000, reactions: [{ emoji: '🚨', users: ['u1', 'u3'] }] },
]

const DEMO_ACTIVITY: ActivityItem[] = [
  { id: 'a1', userId: 'u1', action: 'shared', target: 'STIX bundle with 45 IOCs', timestamp: Date.now() - 300000 },
  { id: 'a2', userId: 'u2', action: 'flagged', target: 'avsvmcloud.com as malicious', timestamp: Date.now() - 240000 },
  { id: 'a3', userId: 'u3', action: 'updated', target: 'investigation timeline', timestamp: Date.now() - 180000 },
  { id: 'a4', userId: 'u4', action: 'joined', target: 'APT29 Investigation room', timestamp: Date.now() - 60000 },
]

const TLP_COLORS = {
  white: { bg: 'bg-white/10', border: 'border-white/30', text: 'text-white' },
  green: { bg: 'bg-green-500/10', border: 'border-green-500/30', text: 'text-green-400' },
  amber: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400' },
  red: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400' },
}

export default function HivemindCollab() {
  const [currentUser] = useState<User>(DEMO_USERS[0])
  const [activeRoom, setActiveRoom] = useState<Room>(DEMO_ROOMS[0])
  const [messages, setMessages] = useState<Message[]>(DEMO_MESSAGES)
  const [newMessage, setNewMessage] = useState('')
  const [showMembers, setShowMembers] = useState(true)
  const [showActivity, setShowActivity] = useState(true)

  // Simulate real-time presence updates
  const [onlineUsers, setOnlineUsers] = useState<User[]>(DEMO_USERS.filter(u => u.status === 'online'))

  useEffect(() => {
    // Simulate user joining/leaving
    const interval = setInterval(() => {
      setOnlineUsers(prev => {
        const randomUser = DEMO_USERS[Math.floor(Math.random() * DEMO_USERS.length)]
        if (prev.find(u => u.id === randomUser.id)) {
          // User might go away
          if (Math.random() > 0.7) {
            return prev.map(u => u.id === randomUser.id ? { ...u, status: 'away' as const } : u)
          }
        }
        return prev
      })
    }, 10000)
    return () => clearInterval(interval)
  }, [])

  // Send message
  const sendMessage = useCallback(() => {
    if (!newMessage.trim()) return

    const message: Message = {
      id: `m-${Date.now()}`,
      userId: currentUser.id,
      content: newMessage,
      timestamp: Date.now(),
      mentions: newMessage.match(/@\w+/g)?.map(m => m.slice(1)),
    }

    setMessages(prev => [...prev, message])
    setNewMessage('')
  }, [newMessage, currentUser.id])

  // Get user by ID
  const getUserById = useCallback((id: string) => {
    return DEMO_USERS.find(u => u.id === id) || { id, name: 'Unknown', color: '#666', role: 'viewer' as const, status: 'offline' as const, lastSeen: 0 }
  }, [])

  // Format timestamp
  const formatTime = useCallback((ts: number) => {
    const diff = Date.now() - ts
    if (diff < 60000) return 'Just now'
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
    return new Date(ts).toLocaleDateString()
  }, [])

  return (
    <div className="h-full flex bg-null-bg">
      {/* Rooms Sidebar */}
      <div className="w-64 border-r border-null-border bg-null-surface flex flex-col">
        <div className="p-4 border-b border-null-border">
          <div className="flex items-center gap-2 text-green-400 mb-3">
            <Globe className="w-5 h-5" />
            <span className="font-display font-bold">HIVEMIND</span>
          </div>
          <button className="w-full px-3 py-2 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 text-sm flex items-center justify-center gap-2 hover:bg-green-500/20 transition-colors">
            <Plus className="w-4 h-4" />
            <span>New Room</span>
          </button>
        </div>

        <div className="flex-1 overflow-auto p-2 space-y-1">
          {DEMO_ROOMS.map(room => {
            const tlp = TLP_COLORS[room.tlpLevel]
            const isActive = activeRoom.id === room.id
            return (
              <button
                key={room.id}
                onClick={() => setActiveRoom(room)}
                className={`w-full p-3 rounded-lg text-left transition-all ${
                  isActive
                    ? 'bg-green-500/10 border border-green-500/30'
                    : 'bg-null-bg border border-transparent hover:border-null-border'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      {room.isPrivate ? (
                        <Lock className="w-3 h-3 text-null-muted" />
                      ) : (
                        <Hash className="w-3 h-3 text-null-muted" />
                      )}
                      <span className="text-sm font-medium text-null-text truncate">{room.name}</span>
                    </div>
                    <p className="text-[10px] text-null-muted mt-1 truncate">{room.description}</p>
                  </div>
                  <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${tlp.bg} ${tlp.border} ${tlp.text} border`}>
                    TLP:{room.tlpLevel.toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-3 mt-2 text-[10px] text-null-muted">
                  <span className="flex items-center gap-1">
                    <Users className="w-3 h-3" />
                    {room.activeUsers} online
                  </span>
                  <span>{formatTime(room.lastActivity)}</span>
                </div>
              </button>
            )
          })}
        </div>

        {/* Current User */}
        <div className="p-3 border-t border-null-border">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div
                className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium"
                style={{ backgroundColor: `${currentUser.color}20`, color: currentUser.color }}
              >
                {currentUser.name.split(' ').map(n => n[0]).join('')}
              </div>
              <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-green-500 border-2 border-null-surface" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm text-null-text truncate">{currentUser.name}</div>
              <div className="text-[10px] text-null-muted capitalize">{currentUser.role}</div>
            </div>
            <button className="p-1.5 rounded hover:bg-null-border/50 text-null-muted">
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Room Header */}
        <div className="p-4 border-b border-null-border bg-null-surface flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              {activeRoom.isPrivate ? <Lock className="w-4 h-4 text-null-muted" /> : <Hash className="w-4 h-4 text-null-muted" />}
              <h2 className="text-sm font-medium text-null-text">{activeRoom.name}</h2>
            </div>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${TLP_COLORS[activeRoom.tlpLevel].bg} ${TLP_COLORS[activeRoom.tlpLevel].border} ${TLP_COLORS[activeRoom.tlpLevel].text} border`}>
              TLP:{activeRoom.tlpLevel.toUpperCase()}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowMembers(!showMembers)}
              className={`p-2 rounded transition-colors ${showMembers ? 'bg-green-500/10 text-green-400' : 'text-null-muted hover:text-null-text'}`}
            >
              <Users className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowActivity(!showActivity)}
              className={`p-2 rounded transition-colors ${showActivity ? 'bg-green-500/10 text-green-400' : 'text-null-muted hover:text-null-text'}`}
            >
              <Activity className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-auto p-4 space-y-4">
          {messages.map((msg, idx) => {
            const user = getUserById(msg.userId)
            const isOwnMessage = msg.userId === currentUser.id
            const showAvatar = idx === 0 || messages[idx - 1].userId !== msg.userId

            return (
              <motion.div
                key={msg.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`flex gap-3 ${isOwnMessage ? 'flex-row-reverse' : ''}`}
              >
                {showAvatar ? (
                  <div
                    className="w-8 h-8 rounded-full flex-shrink-0 flex items-center justify-center text-xs font-medium"
                    style={{ backgroundColor: `${user.color}20`, color: user.color }}
                  >
                    {user.name.split(' ').map(n => n[0]).join('')}
                  </div>
                ) : (
                  <div className="w-8" />
                )}
                <div className={`flex-1 max-w-[70%] ${isOwnMessage ? 'text-right' : ''}`}>
                  {showAvatar && (
                    <div className={`flex items-center gap-2 mb-1 ${isOwnMessage ? 'flex-row-reverse' : ''}`}>
                      <span className="text-xs font-medium" style={{ color: user.color }}>{user.name}</span>
                      <span className="text-[10px] text-null-muted">{formatTime(msg.timestamp)}</span>
                    </div>
                  )}
                  <div className={`inline-block p-3 rounded-lg ${
                    isOwnMessage
                      ? 'bg-green-500/10 border border-green-500/30 text-null-text'
                      : 'bg-null-surface border border-null-border text-null-text'
                  }`}>
                    <p className="text-sm">{msg.content}</p>
                    {msg.attachments && msg.attachments.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {msg.attachments.map((att, i) => (
                          <a
                            key={i}
                            href={att.url}
                            className="flex items-center gap-2 px-2 py-1 rounded bg-null-bg text-xs text-cyan-400 hover:underline"
                          >
                            <Share2 className="w-3 h-3" />
                            {att.name}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                  {msg.reactions && msg.reactions.length > 0 && (
                    <div className={`flex gap-1 mt-1 ${isOwnMessage ? 'justify-end' : ''}`}>
                      {msg.reactions.map((reaction, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-null-surface border border-null-border text-xs">
                          {reaction.emoji} {reaction.users.length}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* Message Input */}
        <div className="p-4 border-t border-null-border bg-null-surface">
          <div className="flex items-center gap-3">
            <div className="flex-1 relative">
              <input
                type="text"
                value={newMessage}
                onChange={(e) => setNewMessage(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
                placeholder={`Message #${activeRoom.name}...`}
                className="w-full px-4 py-2.5 bg-null-bg border border-null-border rounded-lg text-sm text-null-text placeholder:text-null-muted focus:outline-none focus:border-green-500/50"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button className="p-1.5 rounded hover:bg-null-border/50 text-null-muted hover:text-null-text">
                  <AtSign className="w-4 h-4" />
                </button>
                <button className="p-1.5 rounded hover:bg-null-border/50 text-null-muted hover:text-null-text">
                  <Share2 className="w-4 h-4" />
                </button>
              </div>
            </div>
            <button
              onClick={sendMessage}
              disabled={!newMessage.trim()}
              className="px-4 py-2.5 rounded-lg bg-green-500/20 border border-green-500/50 text-green-400 hover:bg-green-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Right Panel - Members & Activity */}
      <AnimatePresence>
        {(showMembers || showActivity) && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 280, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            className="border-l border-null-border bg-null-surface overflow-hidden flex flex-col"
          >
            {/* Members */}
            {showMembers && (
              <div className="border-b border-null-border">
                <div className="p-3 flex items-center justify-between">
                  <h4 className="text-xs font-medium text-null-muted uppercase tracking-wider">
                    Members ({activeRoom.members.length})
                  </h4>
                  <button className="text-null-muted hover:text-null-text">
                    <UserPlus className="w-4 h-4" />
                  </button>
                </div>
                <div className="px-2 pb-3 space-y-1">
                  {activeRoom.members.map(memberId => {
                    const member = getUserById(memberId)
                    return (
                      <div key={member.id} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-null-bg">
                        <div className="relative">
                          <div
                            className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-medium"
                            style={{ backgroundColor: `${member.color}20`, color: member.color }}
                          >
                            {member.name.split(' ').map(n => n[0]).join('')}
                          </div>
                          <div className={`absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2 border-null-surface ${
                            member.status === 'online' ? 'bg-green-500' :
                            member.status === 'away' ? 'bg-yellow-500' :
                            member.status === 'busy' ? 'bg-red-500' : 'bg-gray-500'
                          }`} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="text-xs text-null-text truncate">{member.name}</div>
                          <div className="text-[10px] text-null-muted capitalize">{member.status}</div>
                        </div>
                        {member.role === 'admin' && (
                          <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-[8px] text-purple-400">
                            Admin
                          </span>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Activity Feed */}
            {showActivity && (
              <div className="flex-1 overflow-auto">
                <div className="p-3">
                  <h4 className="text-xs font-medium text-null-muted uppercase tracking-wider mb-3">
                    Recent Activity
                  </h4>
                  <div className="space-y-3">
                    {DEMO_ACTIVITY.map(item => {
                      const user = getUserById(item.userId)
                      const actionIcon = {
                        joined: <UserPlus className="w-3 h-3 text-green-400" />,
                        left: <X className="w-3 h-3 text-red-400" />,
                        commented: <MessageSquare className="w-3 h-3 text-cyan-400" />,
                        updated: <Edit3 className="w-3 h-3 text-yellow-400" />,
                        shared: <Share2 className="w-3 h-3 text-purple-400" />,
                        flagged: <AlertTriangle className="w-3 h-3 text-orange-400" />,
                      }[item.action]

                      return (
                        <div key={item.id} className="flex items-start gap-2">
                          <div className="mt-0.5">{actionIcon}</div>
                          <div className="flex-1 min-w-0">
                            <p className="text-xs text-null-text">
                              <span style={{ color: user.color }}>{user.name}</span>
                              {' '}{item.action}{' '}
                              <span className="text-null-muted">{item.target}</span>
                            </p>
                            <span className="text-[10px] text-null-muted">{formatTime(item.timestamp)}</span>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
