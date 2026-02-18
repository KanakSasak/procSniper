import { useState, useEffect, useRef } from 'react'
import { Shield, ShieldOff, Activity, AlertTriangle, FileWarning, Trash2, Server, Loader2, Target, Ban, Cpu, BarChart3 } from 'lucide-react'
import { useProtection, useDashboardStats, useAlerts } from '../hooks/useWails'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import LogViewer from '../components/LogViewer'

interface ChartDataPoint {
  time: string
  events: number
  threats: number
}

function Dashboard() {
  const { isProtecting, loading, error, startProtection, stopProtection } = useProtection()
  const stats = useDashboardStats()
  const alerts = useAlerts()

  // Chart data - circular buffer of 30 data points
  const [chartData, setChartData] = useState<ChartDataPoint[]>([])
  const prevEventsRef = useRef<number>(0)

  useEffect(() => {
    if (!isProtecting) {
      setChartData([])
      prevEventsRef.current = 0
      return
    }

    const eventsReceived = stats.etwDiagnostics?.eventsReceived || 0
    const newEvents = prevEventsRef.current > 0 ? eventsReceived - prevEventsRef.current : 0
    prevEventsRef.current = eventsReceived

    const now = new Date()
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })

    setChartData((prev) => {
      const next = [...prev, { time: timeStr, events: Math.max(0, newEvents), threats: stats.activeThreatsCount || 0 }]
      return next.slice(-30)
    })
  }, [stats, isProtecting])

  const getStatusColor = () => {
    if (!isProtecting) return 'bg-gray-600'
    if (stats.activeThreatsCount > 0) return 'bg-red-500'
    return 'bg-green-500'
  }

  const getStatusText = () => {
    if (!isProtecting) return 'Protection Stopped'
    if (stats.activeThreatsCount > 0) return 'Threats Detected!'
    return 'Protected'
  }

  return (
    <div className="p-8">
      {/* Header with Protection Toggle */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
            <p className="text-gray-400">Real-time ransomware protection status</p>
          </div>
          <button
            onClick={isProtecting ? stopProtection : startProtection}
            disabled={loading}
            className={`flex items-center gap-3 px-6 py-3 rounded-lg font-semibold transition-all ${
              isProtecting
                ? 'bg-red-600 hover:bg-red-700'
                : 'bg-green-600 hover:bg-green-700'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {loading ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : isProtecting ? (
              <ShieldOff className="w-5 h-5" />
            ) : (
              <Shield className="w-5 h-5" />
            )}
            {loading ? 'Please wait...' : isProtecting ? 'Stop Protection' : 'Start Protection'}
          </button>
        </div>
        {error && (
          <div className="mt-4 p-4 bg-red-500/20 border border-red-500/50 rounded-lg text-red-300">
            {error}
          </div>
        )}
      </div>

      {/* Status Banner */}
      <div className={`${getStatusColor()} rounded-xl p-6 mb-8 transition-colors`}>
        <div className="flex items-center gap-4">
          <div className="p-3 bg-white/20 rounded-full">
            <Shield className="w-8 h-8" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">{getStatusText()}</h2>
            <p className="text-white/80">
              {isProtecting
                ? 'Real-time monitoring is active. Your system is being protected.'
                : 'Click "Start Protection" to enable ransomware monitoring.'}
            </p>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        <StatCard
          icon={<Activity className="w-6 h-6 text-blue-400" />}
          label="Alerts Processed"
          value={stats.alertsProcessed}
          color="blue"
        />
        <StatCard
          icon={<AlertTriangle className="w-6 h-6 text-orange-400" />}
          label="Processes Terminated"
          value={stats.processesTerminated}
          color="orange"
        />
        <StatCard
          icon={<FileWarning className="w-6 h-6 text-yellow-400" />}
          label="Files Quarantined"
          value={stats.filesQuarantined}
          color="yellow"
        />
        <StatCard
          icon={<Target className="w-6 h-6 text-red-400" />}
          label="Active Threats"
          value={stats.activeThreatsCount}
          color="red"
        />
        <StatCard
          icon={<Ban className="w-6 h-6 text-green-400" />}
          label="Responses Blocked"
          value={stats.autoResponsesBlocked}
          color="green"
        />
        <StatCard
          icon={<Trash2 className="w-6 h-6 text-purple-400" />}
          label="Canary Files"
          value={stats.canaryFilesCount}
          color="purple"
        />
      </div>

      {/* Event Activity Chart */}
      {isProtecting && chartData.length > 1 && (
        <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30 mb-8">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-ps-primary" />
            Event Activity
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} width={40} />
              <Tooltip
                contentStyle={{ backgroundColor: '#16213e', border: '1px solid #0f3460', borderRadius: '8px' }}
                labelStyle={{ color: '#9ca3af' }}
              />
              <Area type="monotone" dataKey="events" name="New Events" stroke="#3b82f6" fill="url(#colorEvents)" strokeWidth={2} />
              <Area type="monotone" dataKey="threats" name="Active Threats" stroke="#ef4444" fill="url(#colorThreats)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* System Status + ETW Diagnostics + Entropy */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* System Status */}
        <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Server className="w-5 h-5 text-ps-primary" />
            System Status
          </h3>
          <div className="space-y-4">
            <StatusRow
              label="ETW Connection"
              status={stats.etwConnected}
              statusText={stats.etwConnected ? 'Connected' : 'Disconnected'}
            />
            <StatusRow
              label="Worker Queue"
              status={true}
              statusText={`${stats.workerQueueDepth} events pending`}
            />
            <StatusRow
              label="Protection Status"
              status={isProtecting}
              statusText={stats.protectionStatus}
            />
            <StatusRow
              label="High I/O Processes"
              status={stats.highIOProcessCount === 0}
              statusText={String(stats.highIOProcessCount)}
            />
          </div>
        </div>

        {/* ETW Diagnostics */}
        <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-ps-primary" />
            ETW Diagnostics
          </h3>
          <div className="space-y-3">
            <DiagRow label="Events Received" value={formatNumber(stats.etwDiagnostics?.eventsReceived || 0)} />
            <DiagRow
              label="Events Dropped"
              value={String(stats.etwDiagnostics?.eventsDropped || 0)}
              warn={(stats.etwDiagnostics?.eventsDropped || 0) > 0}
            />
            <DiagRow
              label="Dead PID Suppressed"
              value={String(stats.etwDiagnostics?.eventsSuppressedDeadPID || 0)}
            />
            <DiagRow label="Worker Pool" value={String(stats.etwDiagnostics?.workerPoolSize || 0)} />
            <DiagRow
              label="Channel"
              value={`${stats.etwDiagnostics?.channelLength || 0} / ${stats.etwDiagnostics?.channelCapacity || 0}`}
            />
          </div>
        </div>

        {/* Entropy Monitoring */}
        <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-ps-primary" />
            Entropy Monitoring
          </h3>
          <div className="space-y-3">
            <DiagRow label="Tracked Files" value={String(stats.entropyStats?.trackedFiles || 0)} />
            <DiagRow label="Modified Files" value={String(stats.entropyStats?.modifiedFiles || 0)} />
            <DiagRow
              label="Entropy Increases"
              value={String(stats.entropyStats?.significantIncreases || 0)}
              warn={(stats.entropyStats?.significantIncreases || 0) > 0}
            />
          </div>
          <div className="mt-4 pt-4 border-t border-ps-accent/20">
            <p className="text-xs text-gray-500">
              Tracks Shannon entropy changes in modified files. Significant increases ({'>'}+2.0 bits/byte) may indicate encryption activity.
            </p>
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-ps-darker rounded-xl p-6 border border-ps-accent/30 mb-8">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-ps-primary" />
          Recent Alerts
        </h3>
        {alerts.length === 0 ? (
          <p className="text-gray-400 text-center py-8">No alerts yet</p>
        ) : (
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {alerts.slice(0, 10).map((alert) => (
              <AlertItem key={alert.id} alert={alert} />
            ))}
          </div>
        )}
      </div>

      {/* Log Viewer */}
      <div className="mb-8">
        <LogViewer />
      </div>
    </div>
  )
}

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return String(num)
}

interface StatCardProps {
  icon: React.ReactNode
  label: string
  value: number
  color: 'blue' | 'orange' | 'yellow' | 'purple' | 'red' | 'green'
}

function StatCard({ icon, label, value, color }: StatCardProps) {
  const bgColors = {
    blue: 'bg-blue-500/10',
    orange: 'bg-orange-500/10',
    yellow: 'bg-yellow-500/10',
    purple: 'bg-purple-500/10',
    red: 'bg-red-500/10',
    green: 'bg-green-500/10',
  }

  return (
    <div className={`${bgColors[color]} rounded-xl p-6 border border-ps-accent/30`}>
      <div className="flex items-center gap-4">
        <div className="p-3 bg-ps-accent/50 rounded-lg">{icon}</div>
        <div>
          <p className="text-gray-400 text-sm">{label}</p>
          <p className="text-2xl font-bold">{value}</p>
        </div>
      </div>
    </div>
  )
}

interface StatusRowProps {
  label: string
  status: boolean
  statusText: string
}

function StatusRow({ label, status, statusText }: StatusRowProps) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-gray-400">{label}</span>
      <div className="flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full ${status ? 'bg-green-500' : 'bg-red-500'}`} />
        <span className={status ? 'text-green-400' : 'text-red-400'}>{statusText}</span>
      </div>
    </div>
  )
}

interface DiagRowProps {
  label: string
  value: string
  warn?: boolean
}

function DiagRow({ label, value, warn }: DiagRowProps) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-gray-400 text-sm">{label}</span>
      <span className={`text-sm font-medium ${warn ? 'text-red-400' : 'text-gray-200'}`}>{value}</span>
    </div>
  )
}

interface AlertItemProps {
  alert: {
    id: string
    timestamp: string
    severity: string
    severityColor: string
    category: string
    processName: string
    score: number
    description: string
  }
}

function AlertItem({ alert }: AlertItemProps) {
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString()
  }

  return (
    <div className="bg-ps-accent/30 rounded-lg p-3 border-l-4" style={{ borderColor: alert.severityColor }}>
      <div className="flex items-center justify-between mb-1">
        <span className="font-semibold text-sm">{alert.category}</span>
        <span className="text-xs text-gray-400">{formatTime(alert.timestamp)}</span>
      </div>
      <p className="text-sm text-gray-300 truncate">{alert.description}</p>
      <div className="flex items-center gap-2 mt-1">
        <span className="text-xs text-gray-500 truncate">{alert.processName}</span>
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: alert.severityColor + '30', color: alert.severityColor }}>
          Score: {alert.score}
        </span>
      </div>
    </div>
  )
}

export default Dashboard
