import { useState } from 'react'
import { Shield, ChevronDown, ChevronUp, AlertTriangle } from 'lucide-react'
import { useThreats } from '../hooks/useWails'
import type { Threat } from '../types'

function Threats() {
  const threats = useThreats()
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null)
  const [sortBy, setSortBy] = useState<'score' | 'lastSeen'>('score')

  const sortedThreats = [...threats].sort((a, b) => {
    if (sortBy === 'score') return b.score - a.score
    return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
  })

  const criticalCount = threats.filter((t) => t.threatLevel === 'CRITICAL').length
  const highCount = threats.filter((t) => t.threatLevel === 'HIGH').length
  const mediumCount = threats.filter((t) => t.threatLevel === 'MEDIUM' || t.threatLevel === 'LOW').length

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return '#ef4444'
      case 'HIGH':
        return '#f97316'
      case 'MEDIUM':
        return '#eab308'
      case 'LOW':
        return '#22c55e'
      default:
        return '#6b7280'
    }
  }

  const formatTime = (timestamp: string) => {
    if (!timestamp) return '-'
    const date = new Date(timestamp)
    return date.toLocaleTimeString()
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-3xl font-bold">Active Threats</h1>
          {threats.length > 0 && (
            <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-sm font-semibold">
              {threats.length}
            </span>
          )}
        </div>
        <p className="text-gray-400">Real-time process threat monitoring</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <SummaryCard label="Total Threats" value={threats.length} color="blue" />
        <SummaryCard label="Critical" value={criticalCount} color="red" />
        <SummaryCard label="High" value={highCount} color="orange" />
        <SummaryCard label="Medium / Low" value={mediumCount} color="yellow" />
      </div>

      {/* Sort Controls */}
      {threats.length > 0 && (
        <div className="flex gap-2 mb-4">
          <span className="text-gray-400 text-sm py-1">Sort by:</span>
          <button
            onClick={() => setSortBy('score')}
            className={`px-3 py-1 rounded text-sm ${
              sortBy === 'score' ? 'bg-ps-primary text-white' : 'bg-ps-accent/30 text-gray-400'
            }`}
          >
            Score
          </button>
          <button
            onClick={() => setSortBy('lastSeen')}
            className={`px-3 py-1 rounded text-sm ${
              sortBy === 'lastSeen' ? 'bg-ps-primary text-white' : 'bg-ps-accent/30 text-gray-400'
            }`}
          >
            Last Seen
          </button>
        </div>
      )}

      {/* Threat List */}
      {threats.length === 0 ? (
        <div className="bg-ps-darker rounded-xl p-12 border border-ps-accent/30 text-center">
          <Shield className="w-16 h-16 text-green-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-green-400 mb-2">No Active Threats</h3>
          <p className="text-gray-400">All processes are behaving normally. Your system is protected.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {sortedThreats.map((threat) => (
            <ThreatRow
              key={threat.processGuid}
              threat={threat}
              expanded={expandedThreat === threat.processGuid}
              onToggle={() =>
                setExpandedThreat(expandedThreat === threat.processGuid ? null : threat.processGuid)
              }
              getThreatColor={getThreatColor}
              formatTime={formatTime}
            />
          ))}
        </div>
      )}
    </div>
  )
}

interface SummaryCardProps {
  label: string
  value: number
  color: 'blue' | 'red' | 'orange' | 'yellow'
}

function SummaryCard({ label, value, color }: SummaryCardProps) {
  const bgColors = {
    blue: 'bg-blue-500/10',
    red: 'bg-red-500/10',
    orange: 'bg-orange-500/10',
    yellow: 'bg-yellow-500/10',
  }
  const textColors = {
    blue: 'text-blue-400',
    red: 'text-red-400',
    orange: 'text-orange-400',
    yellow: 'text-yellow-400',
  }

  return (
    <div className={`${bgColors[color]} rounded-xl p-4 border border-ps-accent/30`}>
      <p className="text-gray-400 text-sm">{label}</p>
      <p className={`text-2xl font-bold ${textColors[color]}`}>{value}</p>
    </div>
  )
}

interface ThreatRowProps {
  threat: Threat
  expanded: boolean
  onToggle: () => void
  getThreatColor: (level: string) => string
  formatTime: (timestamp: string) => string
}

function ThreatRow({ threat, expanded, onToggle, getThreatColor, formatTime }: ThreatRowProps) {
  const color = getThreatColor(threat.threatLevel)

  return (
    <div className="bg-ps-darker rounded-xl border border-ps-accent/30 overflow-hidden">
      {/* Main Row */}
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 hover:bg-ps-accent/10 transition-colors text-left"
      >
        <div className="flex items-center gap-4 flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" style={{ color }} />
            <span
              className="px-2 py-0.5 rounded text-xs font-semibold"
              style={{ backgroundColor: color + '30', color }}
            >
              {threat.threatLevel}
            </span>
          </div>
          <div className="min-w-0 flex-1">
            <span className="font-semibold truncate block">{threat.processName || 'Unknown'}</span>
            <span className="text-xs text-gray-500">PID: {threat.processId}</span>
          </div>
          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-gray-500">Category: </span>
              <span className="font-medium">{threat.category}</span>
            </div>
            <div>
              <span className="text-gray-500">Score: </span>
              <span className="font-bold" style={{ color }}>
                {threat.score}
              </span>
            </div>
            <div>
              <span className="text-gray-500">Indicators: </span>
              <span>{threat.indicators?.length || 0}</span>
            </div>
            <div className="text-gray-500 text-xs">{formatTime(threat.lastSeen)}</div>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="w-5 h-5 text-gray-400 ml-2 flex-shrink-0" />
        ) : (
          <ChevronDown className="w-5 h-5 text-gray-400 ml-2 flex-shrink-0" />
        )}
      </button>

      {/* Expanded Details */}
      {expanded && (
        <div className="border-t border-ps-accent/30 p-4 bg-ps-accent/5">
          <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
            <div>
              <span className="text-gray-500">Process GUID: </span>
              <span className="font-mono text-xs">{threat.processGuid}</span>
            </div>
            <div>
              <span className="text-gray-500">First Seen: </span>
              <span>{formatTime(threat.firstSeen)}</span>
            </div>
          </div>

          <h4 className="text-sm font-semibold mb-3 text-gray-300">
            Indicators ({threat.indicators?.length || 0})
          </h4>
          <div className="space-y-2">
            {threat.indicators?.map((ind, idx) => (
              <div key={idx} className="bg-ps-accent/20 rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-ps-accent/50 rounded text-xs font-mono">
                      {ind.type}
                    </span>
                    <span className="text-xs text-gray-500">{ind.severity}</span>
                  </div>
                  <span className="text-sm font-bold text-ps-primary">+{ind.points} pts</span>
                </div>
                <p className="text-sm text-gray-300">{ind.description}</p>
                {ind.evidence && Object.keys(ind.evidence).length > 0 && (
                  <div className="mt-2 text-xs text-gray-500">
                    {Object.entries(ind.evidence).map(([key, value]) => (
                      <div key={key}>
                        <span className="font-medium">{key}:</span> {value}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default Threats
