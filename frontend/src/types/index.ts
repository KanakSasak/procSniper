// ETW Diagnostics
export interface ETWDiagnostics {
  eventsReceived: number
  eventsDropped: number
  eventsSuppressedDeadPID: number
  workerPoolSize: number
  channelCapacity: number
  channelLength: number
}

// Entropy Stats
export interface EntropyStats {
  trackedFiles: number
  modifiedFiles: number
  significantIncreases: number
}

// Dashboard statistics
export interface DashboardStats {
  protectionStatus: string
  etwConnected: boolean
  workerQueueDepth: number
  alertsProcessed: number
  processesTerminated: number
  filesQuarantined: number
  canaryFilesCount: number
  activeThreatsCount: number
  autoResponsesBlocked: number
  highIOProcessCount: number
  etwDiagnostics: ETWDiagnostics
  entropyStats: EntropyStats
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

// Threat view model
export interface Threat {
  processGuid: string
  processName: string
  processId: number
  score: number
  threatLevel: string
  category: string
  firstSeen: string
  lastSeen: string
  indicators: Indicator[]
}

// ML Model Status
export interface MLModelStatus {
  loaded: boolean
  filePath: string
  modelName: string
  modelType: string
  loadedAt: string
  enabled: boolean
  featureCount: number
  confidenceThreshold: number
}

// ML Prediction result from ONNX inference
export interface MLPrediction {
  processName: string
  processId: number
  label: string           // "benign", "ransomware", "stealer"
  confidence: number      // 0.0-1.0
  probabilities: number[] // [benign, ransomware, stealer]
  stage: string           // skipped, predicted, decision, error
  reason: string
  decision: string        // terminate_eligible, alert_only, none
  decisionCategory: string
  decisionScore: number
  decisionAutoRespond: boolean
  threshold: number
  modeEnabled: boolean
  predictorReady: boolean
  error: string
  timestamp: string
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
  ransomwareExtensionRenameThreshold: number
  combinedEntropyAndExtensionThreshold: number
  ioVelocityThresholdPerMinute: number
}

export interface ResponseSettings {
  autoTerminateEnabled: boolean
  criticalScoreThreshold: number
  investigationMode: boolean
  quarantineFiles: boolean
  quarantineDirectory: string
  immediateResponse: boolean
  terminateOnExtensionMatch: boolean
  suspendBeforeTerminate: boolean
  detectionMode: string        // "rules_only", "hybrid", "ml_only"
  canaryResponseAction: string // "terminate", "suspend", "alert_only"
}

export interface Whitelist {
  enabled: boolean
  paths: string[]
  processes: string[]
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
