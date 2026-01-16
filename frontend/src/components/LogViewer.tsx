import { useEffect, useRef } from 'react'
import { Terminal, Trash2, ArrowDown, Pause, Play } from 'lucide-react'
import { useLogs } from '../hooks/useWails'

function LogViewer() {
  const { logs, clearLogs, autoScroll, setAutoScroll } = useLogs(300)
  const containerRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  const getLevelColor = (level: string): string => {
    switch (level.toUpperCase()) {
      case 'ERROR':
        return 'text-red-400'
      case 'WARN':
      case 'WARNING':
        return 'text-yellow-400'
      case 'SUCCESS':
        return 'text-green-400'
      case 'ALERT':
        return 'text-orange-400'
      case 'DEBUG':
        return 'text-gray-500'
      default:
        return 'text-gray-300'
    }
  }

  const getLevelBadgeColor = (level: string): string => {
    switch (level.toUpperCase()) {
      case 'ERROR':
        return 'bg-red-500/20 text-red-400 border-red-500/50'
      case 'WARN':
      case 'WARNING':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
      case 'SUCCESS':
        return 'bg-green-500/20 text-green-400 border-green-500/50'
      case 'ALERT':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/50'
      case 'DEBUG':
        return 'bg-gray-500/20 text-gray-500 border-gray-500/50'
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/50'
    }
  }

  // Remove ANSI codes and clean up message
  const cleanMessage = (message: string): string => {
    // Remove ANSI escape codes
    return message
      .replace(/\x1b\[[0-9;]*m/g, '')
      .replace(/\[0m/g, '')
      .replace(/\[0;[0-9]+m/g, '')
      .trim()
  }

  return (
    <div className="bg-ps-darker rounded-xl border border-ps-accent/30 flex flex-col h-[400px]">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-ps-accent/30">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-ps-primary" />
          <h3 className="text-lg font-semibold">Live Logs</h3>
          <span className="text-xs text-gray-500">({logs.length} entries)</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm transition-colors ${
              autoScroll
                ? 'bg-green-500/20 text-green-400 border border-green-500/50'
                : 'bg-ps-accent/30 text-gray-400 border border-ps-accent/50'
            }`}
            title={autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll disabled'}
          >
            {autoScroll ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            Auto
          </button>
          <button
            onClick={() => {
              if (containerRef.current) {
                containerRef.current.scrollTop = containerRef.current.scrollHeight
              }
            }}
            className="p-1.5 rounded-lg bg-ps-accent/30 text-gray-400 hover:text-white transition-colors"
            title="Scroll to bottom"
          >
            <ArrowDown className="w-4 h-4" />
          </button>
          <button
            onClick={clearLogs}
            className="p-1.5 rounded-lg bg-ps-accent/30 text-gray-400 hover:text-red-400 transition-colors"
            title="Clear logs"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Log entries */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto font-mono text-xs p-2 space-y-0.5"
      >
        {logs.length === 0 ? (
          <div className="text-gray-500 text-center py-8">
            No logs yet. Start protection to see activity.
          </div>
        ) : (
          logs.map((log, index) => (
            <div
              key={index}
              className={`flex items-start gap-2 py-0.5 px-2 rounded hover:bg-ps-accent/20 ${getLevelColor(log.level)}`}
            >
              <span className="text-gray-500 shrink-0 w-20">{log.timestamp}</span>
              <span
                className={`shrink-0 px-1.5 py-0.5 text-[10px] rounded border ${getLevelBadgeColor(log.level)}`}
              >
                {log.level.substring(0, 5).toUpperCase()}
              </span>
              <span className="break-all whitespace-pre-wrap">{cleanMessage(log.message)}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default LogViewer
