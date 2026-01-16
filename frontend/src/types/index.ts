// Dashboard statistics
export interface DashboardStats {
  protectionStatus: string
  sysmonConnected: boolean
  workerQueueDepth: number
  alertsProcessed: number
  processesTerminated: number
  filesQuarantined: number
  canaryFilesCount: number
  activeThreatsCount: number
}

// Alert types
export interface Alert {
  id: string
  timestamp: string
  severity: string
  severityColor: string
  category: string
  processName: string
  processId: number
  processGuid: string
  description: string
  score: number
  indicatorCount: number
  indicators: Indicator[]
  autoResponded: boolean
  responseActions: string[]
}

export interface Indicator {
  type: string
  severity: string
  points: number
  description: string
  timestamp: string
  evidence: Record<string, string>
}

// Configuration types
export interface Config {
  version: string
  lastUpdated: string
  detectionThresholds: DetectionThresholds
  responseSettings: ResponseSettings
  whitelist: Whitelist
  ransomwareExtensions: string[]
}

export interface DetectionThresholds {
  highEntropyFileThreshold: number
  ransomwareExtensionFileThreshold: number
  combinedEntropyAndExtensionThreshold: number
}

export interface ResponseSettings {
  autoTerminateEnabled: boolean
  criticalScoreThreshold: number
  investigationMode: boolean
  quarantineFiles: boolean
  quarantineDirectory: string
}

export interface Whitelist {
  enabled: boolean
  paths: string[]
}

// Operation result
export interface OperationResult {
  success: boolean
  message: string
}

// Log entry
export interface LogEntry {
  timestamp: string
  level: string
  message: string
}
