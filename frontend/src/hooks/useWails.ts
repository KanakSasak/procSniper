import { useEffect, useState, useCallback, useRef } from 'react'
import type { DashboardStats, Config, OperationResult, Alert, LogEntry, Threat, MLModelStatus, MLPrediction } from '../types'

// Transport: the React console is served by the headless agent (internal/delivery/api) and talks to
// it over a local HTTP+SSE API on the same origin. (This replaced the in-process Wails bindings; the
// hook signatures below are unchanged so the components didn't need to.)

// --- auth token ---
// The tray/operator opens the console with the bearer token in the URL fragment (#token=...). We
// capture it once, persist for the session, and strip it from the address bar.
function readToken(): string {
  const m = window.location.hash.match(/token=([0-9a-fA-F]+)/)
  if (m) {
    sessionStorage.setItem('apiToken', m[1])
    history.replaceState(null, '', window.location.pathname + window.location.search)
    return m[1]
  }
  return sessionStorage.getItem('apiToken') || ''
}
const TOKEN = readToken()

const authHeaders = (): Record<string, string> => ({ Authorization: `Bearer ${TOKEN}` })

async function apiGet<T>(path: string): Promise<T> {
  const r = await fetch(path, { headers: authHeaders() })
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return (await r.json()) as T
}

async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return (await r.json()) as T
}

async function apiDelete(path: string): Promise<void> {
  await fetch(path, { method: 'DELETE', headers: authHeaders() })
}

// --- shared SSE bus (one EventSource for all hooks) ---
type Handler = (data: unknown) => void
const SSE_EVENTS = ['stats:update', 'threat:update', 'alert:new', 'log:entry', 'ml:prediction']
let es: EventSource | null = null
const handlers: Record<string, Set<Handler>> = {}

function ensureSSE() {
  if (es) return
  es = new EventSource(`/api/stream?token=${encodeURIComponent(TOKEN)}`)
  for (const ev of SSE_EVENTS) {
    es.addEventListener(ev, (e: MessageEvent) => {
      let data: unknown = e.data
      try { data = JSON.parse(e.data) } catch { /* keep raw */ }
      handlers[ev]?.forEach((h) => h(data))
    })
  }
  // EventSource auto-reconnects on error; nothing to do.
}

function subscribe(event: string, cb: Handler): () => void {
  ensureSSE()
  ;(handlers[event] ||= new Set()).add(cb)
  return () => { handlers[event]?.delete(cb) }
}

const defaultStats: DashboardStats = {
  protectionStatus: 'Stopped',
  etwConnected: false,
  workerQueueDepth: 0,
  alertsProcessed: 0,
  processesTerminated: 0,
  filesQuarantined: 0,
  canaryFilesCount: 0,
  activeThreatsCount: 0,
  autoResponsesBlocked: 0,
  highIOProcessCount: 0,
  etwDiagnostics: {
    eventsReceived: 0,
    eventsDropped: 0,
    eventsSuppressedDeadPID: 0,
    workerPoolSize: 0,
    channelCapacity: 0,
    channelLength: 0,
  },
  entropyStats: {
    trackedFiles: 0,
    modifiedFiles: 0,
    significantIncreases: 0,
  },
}

export function useProtection() {
  const [isProtecting, setIsProtecting] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const checkStatus = useCallback(async () => {
    try {
      const r = await apiGet<{ protecting: boolean }>('/api/protect/status')
      setIsProtecting(r.protecting)
    } catch (err) {
      console.error('Failed to check protection status:', err)
    }
  }, [])

  useEffect(() => { checkStatus() }, [checkStatus])

  const startProtection = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await apiPost<OperationResult>('/api/protect/start')
      if (result.success) setIsProtecting(true)
      else setError(result.message)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start protection')
    } finally {
      setLoading(false)
    }
  }, [])

  const stopProtection = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await apiPost<OperationResult>('/api/protect/stop')
      if (result.success) setIsProtecting(false)
      else setError(result.message)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop protection')
    } finally {
      setLoading(false)
    }
  }, [])

  return { isProtecting, loading, error, startProtection, stopProtection }
}

export function useDashboardStats() {
  const [stats, setStats] = useState<DashboardStats>(defaultStats)

  useEffect(() => {
    apiGet<DashboardStats>('/api/stats').then(setStats).catch((err) => console.error('Failed to fetch stats:', err))
    return subscribe('stats:update', (data) => setStats(data as DashboardStats))
  }, [])

  return stats
}

export function useAlerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])

  useEffect(() => {
    return subscribe('alert:new', (data) => {
      setAlerts((prev) => [data as Alert, ...prev].slice(0, 100))
    })
  }, [])

  return alerts
}

export function useThreats() {
  const [threats, setThreats] = useState<Threat[]>([])

  useEffect(() => {
    apiGet<Threat[]>('/api/threats').then((d) => setThreats(d || [])).catch((err) => console.error('Failed to fetch threats:', err))
    return subscribe('threat:update', (data) => setThreats((data as Threat[]) || []))
  }, [])

  return threats
}

export function useMLModel() {
  const [status, setStatus] = useState<MLModelStatus>({
    loaded: false,
    filePath: '',
    modelName: '',
    modelType: '',
    loadedAt: '',
    enabled: false,
    featureCount: 0,
    confidenceThreshold: 0.75,
  })
  const [loading, setLoading] = useState(false)
  const [predictions, setPredictions] = useState<MLPrediction[]>([])

  const fetchStatus = useCallback(async () => {
    try {
      setStatus(await apiGet<MLModelStatus>('/api/ml/status'))
    } catch (err) {
      console.error('Failed to fetch ML model status:', err)
    }
  }, [])

  useEffect(() => { fetchStatus() }, [fetchStatus])

  useEffect(() => {
    return subscribe('ml:prediction', (pred) => {
      setPredictions((prev) => [pred as MLPrediction, ...prev].slice(0, 100))
    })
  }, [])

  // The model lives on the server (the agent loads it server-side), so we ask for a server-side
  // path rather than a native file dialog. (v1: a prompt; a path-input UI is a follow-up.)
  const selectAndLoadModel = useCallback(async () => {
    const filePath = window.prompt('Path to the .onnx model on the agent host:')
    if (!filePath) return { success: false, message: 'No path provided' }
    setLoading(true)
    try {
      const result = await apiPost<OperationResult>('/api/ml/load', { filePath })
      if (result.success) await fetchStatus()
      return result
    } finally {
      setLoading(false)
    }
  }, [fetchStatus])

  const unloadModel = useCallback(async () => {
    const result = await apiPost<OperationResult>('/api/ml/unload')
    if (result.success) await fetchStatus()
    return result
  }, [fetchStatus])

  const setEnabled = useCallback(async (enabled: boolean) => {
    const result = await apiPost<OperationResult>('/api/ml/enable', { enabled })
    if (result.success) await fetchStatus()
    return result
  }, [fetchStatus])

  const setThreshold = useCallback(async (threshold: number) => {
    const result = await apiPost<OperationResult>('/api/ml/confidence', { threshold })
    if (result.success) await fetchStatus()
    return result
  }, [fetchStatus])

  return { status, loading, predictions, selectAndLoadModel, unloadModel, setEnabled, setThreshold }
}

export function useConfiguration() {
  const [config, setConfig] = useState<Config | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadConfig = useCallback(async () => {
    setLoading(true)
    try {
      setConfig(await apiGet<Config>('/api/config'))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load configuration')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadConfig() }, [loadConfig])

  const saveConfig = useCallback(async (newConfig: Config) => {
    setSaving(true)
    setError(null)
    try {
      const result = await apiPost<OperationResult>('/api/config', newConfig)
      if (result.success) setConfig(newConfig)
      else setError(result.message)
      return result
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save configuration'
      setError(message)
      return { success: false, message }
    } finally {
      setSaving(false)
    }
  }, [])

  return { config, loading, saving, error, saveConfig, reload: loadConfig }
}

export function useLogs(maxEntries: number = 200) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [autoScroll, setAutoScroll] = useState(true)
  const logsRef = useRef<LogEntry[]>([])

  useEffect(() => {
    apiGet<LogEntry[]>(`/api/logs?limit=${maxEntries}`)
      .then((data) => { setLogs(data || []); logsRef.current = data || [] })
      .catch((err) => console.error('Failed to load logs:', err))

    // Live log entries arrive over the shared SSE stream while protection is running.
    return subscribe('log:entry', (data) => {
      logsRef.current = [...logsRef.current, data as LogEntry].slice(-maxEntries)
      setLogs([...logsRef.current])
    })
  }, [maxEntries])

  const clearLogs = useCallback(async () => {
    try {
      await apiDelete('/api/logs')
      setLogs([])
      logsRef.current = []
    } catch (err) {
      console.error('Failed to clear logs:', err)
    }
  }, [])

  return { logs, clearLogs, autoScroll, setAutoScroll }
}
