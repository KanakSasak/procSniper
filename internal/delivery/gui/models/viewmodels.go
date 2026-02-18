//go:build windows

package models

import (
	"time"

	"procSniper/internal/domain"
)

// OperationResult represents the result of an operation
type OperationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ETWDiagnosticsVM represents ETW diagnostic stats for the frontend
type ETWDiagnosticsVM struct {
	EventsReceived          uint64 `json:"eventsReceived"`
	EventsDropped           uint64 `json:"eventsDropped"`
	EventsSuppressedDeadPID uint64 `json:"eventsSuppressedDeadPID"`
	WorkerPoolSize          int    `json:"workerPoolSize"`
	ChannelCapacity         int    `json:"channelCapacity"`
	ChannelLength           int    `json:"channelLength"`
}

// EntropyStatsVM represents entropy tracker statistics for the frontend
type EntropyStatsVM struct {
	TrackedFiles         int `json:"trackedFiles"`
	ModifiedFiles        int `json:"modifiedFiles"`
	SignificantIncreases int `json:"significantIncreases"`
}

// MLModelStatus represents ML model state for the frontend
type MLModelStatus struct {
	Loaded              bool    `json:"loaded"`
	FilePath            string  `json:"filePath"`
	ModelName           string  `json:"modelName"`
	ModelType           string  `json:"modelType"`
	LoadedAt            string  `json:"loadedAt"`
	Enabled             bool    `json:"enabled"`
	FeatureCount        int     `json:"featureCount"`
	ConfidenceThreshold float64 `json:"confidenceThreshold"`
}

// MLPredictionVM represents a single ML prediction for the frontend
type MLPredictionVM struct {
	ProcessName         string     `json:"processName"`
	ProcessID           int        `json:"processId"`
	Label               string     `json:"label"`         // "benign", "ransomware", "stealer"
	Confidence          float64    `json:"confidence"`    // 0.0-1.0
	Probabilities       [3]float64 `json:"probabilities"` // [benign, ransomware, stealer]
	Stage               string     `json:"stage"`         // skipped, predicted, decision, error
	Reason              string     `json:"reason"`        // predictor_not_ready, below_threshold, benign_label, inference_error
	Decision            string     `json:"decision"`      // terminate_eligible, alert_only, none
	DecisionCategory    string     `json:"decisionCategory"`
	DecisionScore       int        `json:"decisionScore"`
	DecisionAutoRespond bool       `json:"decisionAutoRespond"`
	Threshold           float64    `json:"threshold"`
	ModeEnabled         bool       `json:"modeEnabled"`
	PredictorReady      bool       `json:"predictorReady"`
	Error               string     `json:"error"`
	Timestamp           string     `json:"timestamp"`
}

// DashboardStats represents statistics for the dashboard
type DashboardStats struct {
	ProtectionStatus     string           `json:"protectionStatus"`
	ETWConnected         bool             `json:"etwConnected"`
	WorkerQueueDepth     int              `json:"workerQueueDepth"`
	AlertsProcessed      int              `json:"alertsProcessed"`
	ProcessesTerminated  int              `json:"processesTerminated"`
	FilesQuarantined     int              `json:"filesQuarantined"`
	CanaryFilesCount     int              `json:"canaryFilesCount"`
	ActiveThreatsCount   int              `json:"activeThreatsCount"`
	AutoResponsesBlocked int              `json:"autoResponsesBlocked"`
	HighIOProcessCount   int              `json:"highIOProcessCount"`
	ETWDiagnostics       ETWDiagnosticsVM `json:"etwDiagnostics"`
	EntropyStats         EntropyStatsVM   `json:"entropyStats"`
}

// AlertViewModel represents an alert for the frontend
type AlertViewModel struct {
	ID              string        `json:"id"`
	Timestamp       string        `json:"timestamp"`
	Severity        string        `json:"severity"`
	SeverityColor   string        `json:"severityColor"`
	Category        string        `json:"category"`
	ProcessName     string        `json:"processName"`
	ProcessID       int           `json:"processId"`
	ProcessGuid     string        `json:"processGuid"`
	Description     string        `json:"description"`
	Score           int           `json:"score"`
	IndicatorCount  int           `json:"indicatorCount"`
	Indicators      []IndicatorVM `json:"indicators"`
	AutoResponded   bool          `json:"autoResponded"`
	ResponseActions []string      `json:"responseActions"`
}

// IndicatorVM represents a threat indicator for the frontend
type IndicatorVM struct {
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Points      int               `json:"points"`
	Description string            `json:"description"`
	Timestamp   string            `json:"timestamp"`
	Evidence    map[string]string `json:"evidence"`
}

// ThreatViewModel represents a threat for the frontend
type ThreatViewModel struct {
	ProcessGuid string        `json:"processGuid"`
	ProcessName string        `json:"processName"`
	ProcessID   int           `json:"processId"`
	Score       int           `json:"score"`
	ThreatLevel string        `json:"threatLevel"`
	Category    string        `json:"category"`
	FirstSeen   string        `json:"firstSeen"`
	LastSeen    string        `json:"lastSeen"`
	Indicators  []IndicatorVM `json:"indicators"`
}

// ConfigViewModel represents configuration for the frontend
type ConfigViewModel struct {
	Version              string                `json:"version"`
	LastUpdated          string                `json:"lastUpdated"`
	DetectionThresholds  DetectionThresholdsVM `json:"detectionThresholds"`
	ResponseSettings     ResponseSettingsVM    `json:"responseSettings"`
	Whitelist            WhitelistVM           `json:"whitelist"`
	RansomwareExtensions []string              `json:"ransomwareExtensions"`
}

// DetectionThresholdsVM represents detection thresholds
type DetectionThresholdsVM struct {
	HighEntropyFileThreshold             int `json:"highEntropyFileThreshold"`
	RansomwareExtensionFileThreshold     int `json:"ransomwareExtensionFileThreshold"`
	RansomwareExtensionRenameThreshold   int `json:"ransomwareExtensionRenameThreshold"`
	CombinedEntropyAndExtensionThreshold int `json:"combinedEntropyAndExtensionThreshold"`
	IOVelocityThresholdPerMinute         int `json:"ioVelocityThresholdPerMinute"`
}

// ResponseSettingsVM represents response settings
type ResponseSettingsVM struct {
	AutoTerminateEnabled      bool   `json:"autoTerminateEnabled"`
	CriticalScoreThreshold    int    `json:"criticalScoreThreshold"`
	InvestigationMode         bool   `json:"investigationMode"`
	QuarantineFiles           bool   `json:"quarantineFiles"`
	QuarantineDirectory       string `json:"quarantineDirectory"`
	ImmediateResponse         bool   `json:"immediateResponse"`
	TerminateOnExtensionMatch bool   `json:"terminateOnExtensionMatch"`
	SuspendBeforeTerminate    bool   `json:"suspendBeforeTerminate"`
	DetectionMode             string `json:"detectionMode"`        // "rules_only", "hybrid", "ml_only"
	CanaryResponseAction      string `json:"canaryResponseAction"` // "terminate", "suspend", "alert_only"
}

// WhitelistVM represents whitelist configuration
type WhitelistVM struct {
	Enabled   bool     `json:"enabled"`
	Paths     []string `json:"paths"`
	Processes []string `json:"processes"`
}

// AlertFromDomain converts a domain Alert to AlertViewModel
func AlertFromDomain(alert *domain.Alert) AlertViewModel {
	if alert == nil {
		return AlertViewModel{}
	}

	severityColor := getSeverityColor(alert.Severity)
	indicators := make([]IndicatorVM, 0, len(alert.Indicators))

	for _, ind := range alert.Indicators {
		indicators = append(indicators, IndicatorVM{
			Type:        string(ind.Type),
			Severity:    string(ind.Severity),
			Points:      ind.Points,
			Description: ind.Description,
			Timestamp:   ind.Timestamp.Format(time.RFC3339),
			Evidence:    ind.Evidence,
		})
	}

	return AlertViewModel{
		ID:              alert.ID,
		Timestamp:       alert.Timestamp.Format(time.RFC3339),
		Severity:        string(alert.Severity),
		SeverityColor:   severityColor,
		Category:        alert.Category,
		ProcessName:     alert.Image, // Image contains the process path
		ProcessID:       alert.ProcessID,
		ProcessGuid:     alert.ProcessGuid,
		Description:     alert.Description,
		Score:           alert.Score,
		IndicatorCount:  len(alert.Indicators),
		Indicators:      indicators,
		AutoResponded:   alert.AutoRespond,
		ResponseActions: alert.ResponseActions,
	}
}

// ThreatFromDomain converts a domain ThreatScore to ThreatViewModel
func ThreatFromDomain(score *domain.ThreatScore) ThreatViewModel {
	if score == nil {
		return ThreatViewModel{}
	}

	level := evaluateThreatLevel(score.Score)

	indicators := make([]IndicatorVM, 0, len(score.Indicators))
	for _, ind := range score.Indicators {
		indicators = append(indicators, IndicatorVM{
			Type:        string(ind.Type),
			Severity:    string(ind.Severity),
			Points:      ind.Points,
			Description: ind.Description,
			Timestamp:   ind.Timestamp.Format(time.RFC3339),
			Evidence:    ind.Evidence,
		})
	}

	return ThreatViewModel{
		ProcessGuid: score.ProcessGuid,
		ProcessName: score.Image,
		ProcessID:   score.ProcessID,
		Score:       score.Score,
		ThreatLevel: string(level),
		Category:    score.Category,
		FirstSeen:   score.FirstSeen.Format(time.RFC3339),
		LastSeen:    score.LastSeen.Format(time.RFC3339),
		Indicators:  indicators,
	}
}

// evaluateThreatLevel maps a score to a ThreatLevel
func evaluateThreatLevel(score int) domain.ThreatLevel {
	switch {
	case score >= 86:
		return domain.ThreatCritical
	case score >= 61:
		return domain.ThreatHigh
	case score >= 31:
		return domain.ThreatMedium
	case score >= 1:
		return domain.ThreatLow
	default:
		return domain.ThreatNone
	}
}

// getSeverityColor returns the color for a threat level
func getSeverityColor(level domain.ThreatLevel) string {
	switch level {
	case domain.ThreatCritical:
		return "#ef4444" // red-500
	case domain.ThreatHigh:
		return "#f97316" // orange-500
	case domain.ThreatMedium:
		return "#eab308" // yellow-500
	case domain.ThreatLow:
		return "#22c55e" // green-500
	default:
		return "#6b7280" // gray-500
	}
}
