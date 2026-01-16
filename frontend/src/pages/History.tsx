import { useState } from 'react'
import { Search, Download, Clock, ChevronDown, ChevronUp } from 'lucide-react'
import { useAlerts } from '../hooks/useWails'
import type { Alert } from '../types'

function History() {
  const alerts = useAlerts()
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all')
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null)

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.processName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.category.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity = selectedSeverity === 'all' || alert.severity.toLowerCase() === selectedSeverity.toLowerCase()

    return matchesSearch && matchesSeverity
  })

  const exportToCSV = () => {
    const headers = ['Timestamp', 'Severity', 'Category', 'Process', 'Score', 'Description']
    const rows = filteredAlerts.map((alert) => [
      alert.timestamp,
      alert.severity,
      alert.category,
      alert.processName,
      alert.score.toString(),
      `"${alert.description.replace(/"/g, '""')}"`,
    ])

    const csv = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `procsniper-alerts-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold mb-2">Alert History</h1>
          <p className="text-gray-400">Review past detections and incidents</p>
        </div>
        <button
          onClick={exportToCSV}
          disabled={filteredAlerts.length === 0}
          className="flex items-center gap-2 px-4 py-2 bg-ps-primary rounded-lg hover:bg-ps-primary/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-4 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-ps-darker border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary"
          />
        </div>
        <select
          value={selectedSeverity}
          onChange={(e) => setSelectedSeverity(e.target.value)}
          className="px-4 py-2 bg-ps-darker border border-ps-accent/50 rounded-lg focus:outline-none focus:border-ps-primary"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatBox label="Total Alerts" value={alerts.length} />
        <StatBox
          label="Critical"
          value={alerts.filter((a) => a.severity.toLowerCase() === 'critical').length}
          color="red"
        />
        <StatBox
          label="High"
          value={alerts.filter((a) => a.severity.toLowerCase() === 'high').length}
          color="orange"
        />
        <StatBox
          label="Medium/Low"
          value={alerts.filter((a) => ['medium', 'low'].includes(a.severity.toLowerCase())).length}
          color="yellow"
        />
      </div>

      {/* Alerts Table */}
      <div className="bg-ps-darker rounded-xl border border-ps-accent/30 overflow-hidden">
        {filteredAlerts.length === 0 ? (
          <div className="p-12 text-center">
            <Clock className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No alerts to display</p>
            <p className="text-gray-500 text-sm mt-2">
              {alerts.length === 0
                ? 'Alerts will appear here when threats are detected'
                : 'No alerts match your search criteria'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-ps-accent/30">
            {filteredAlerts.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                isExpanded={expandedAlert === alert.id}
                onToggle={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}
                formatTimestamp={formatTimestamp}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

interface StatBoxProps {
  label: string
  value: number
  color?: 'red' | 'orange' | 'yellow'
}

function StatBox({ label, value, color }: StatBoxProps) {
  const colorClasses = {
    red: 'text-red-400',
    orange: 'text-orange-400',
    yellow: 'text-yellow-400',
  }

  return (
    <div className="bg-ps-darker p-4 rounded-lg border border-ps-accent/30">
      <p className="text-gray-400 text-sm">{label}</p>
      <p className={`text-2xl font-bold ${color ? colorClasses[color] : 'text-white'}`}>{value}</p>
    </div>
  )
}

interface AlertRowProps {
  alert: Alert
  isExpanded: boolean
  onToggle: () => void
  formatTimestamp: (timestamp: string) => string
}

function AlertRow({ alert, isExpanded, onToggle, formatTimestamp }: AlertRowProps) {
  return (
    <div>
      <div
        className="flex items-center gap-4 p-4 cursor-pointer hover:bg-ps-accent/10 transition-colors"
        onClick={onToggle}
      >
        <div
          className="w-3 h-3 rounded-full"
          style={{ backgroundColor: alert.severityColor }}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold">{alert.category}</span>
            <span
              className="text-xs px-2 py-0.5 rounded"
              style={{ backgroundColor: alert.severityColor + '30', color: alert.severityColor }}
            >
              {alert.severity}
            </span>
          </div>
          <p className="text-sm text-gray-400 truncate">{alert.description}</p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-300">{formatTimestamp(alert.timestamp)}</p>
          <p className="text-xs text-gray-500">Score: {alert.score}</p>
        </div>
        {isExpanded ? (
          <ChevronUp className="w-5 h-5 text-gray-400" />
        ) : (
          <ChevronDown className="w-5 h-5 text-gray-400" />
        )}
      </div>

      {isExpanded && (
        <div className="px-4 pb-4 bg-ps-accent/5">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <p className="text-xs text-gray-500 uppercase">Process</p>
              <p className="text-sm font-mono break-all">{alert.processName}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase">Process ID</p>
              <p className="text-sm">{alert.processId}</p>
            </div>
          </div>

          {alert.indicators.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 uppercase mb-2">Indicators ({alert.indicatorCount})</p>
              <div className="space-y-2">
                {alert.indicators.map((indicator, index) => (
                  <div key={index} className="bg-ps-accent/20 p-3 rounded-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-semibold">{indicator.type}</span>
                      <span className="text-xs text-ps-primary">+{indicator.points} points</span>
                    </div>
                    <p className="text-xs text-gray-400">{indicator.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {alert.responseActions.length > 0 && (
            <div className="mt-4">
              <p className="text-xs text-gray-500 uppercase mb-2">Response Actions</p>
              <div className="flex flex-wrap gap-2">
                {alert.responseActions.map((action, index) => (
                  <span key={index} className="text-xs bg-ps-primary/20 text-ps-primary px-2 py-1 rounded">
                    {action}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default History
