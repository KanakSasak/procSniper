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

// DashboardStats represents statistics for the dashboard
type DashboardStats struct {
	ProtectionStatus    string `json:"protectionStatus"`
	SysmonConnected     bool   `json:"sysmonConnected"`
	WorkerQueueDepth    int    `json:"workerQueueDepth"`
	AlertsProcessed     int    `json:"alertsProcessed"`
	ProcessesTerminated int    `json:"processesTerminated"`
	FilesQuarantined    int    `json:"filesQuarantined"`
	CanaryFilesCount    int    `json:"canaryFilesCount"`
	ActiveThreatsCount  int    `json:"activeThreatsCount"`
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
	Version              string               `json:"version"`
	LastUpdated          string               `json:"lastUpdated"`
	DetectionThresholds  DetectionThresholdsVM `json:"detectionThresholds"`
	ResponseSettings     ResponseSettingsVM   `json:"responseSettings"`
	Whitelist            WhitelistVM          `json:"whitelist"`
	RansomwareExtensions []string             `json:"ransomwareExtensions"`
}

// DetectionThresholdsVM represents detection thresholds
type DetectionThresholdsVM struct {
	HighEntropyFileThreshold             int `json:"highEntropyFileThreshold"`
	RansomwareExtensionFileThreshold     int `json:"ransomwareExtensionFileThreshold"`
	CombinedEntropyAndExtensionThreshold int `json:"combinedEntropyAndExtensionThreshold"`
}

// ResponseSettingsVM represents response settings
type ResponseSettingsVM struct {
	AutoTerminateEnabled   bool   `json:"autoTerminateEnabled"`
	CriticalScoreThreshold int    `json:"criticalScoreThreshold"`
	InvestigationMode      bool   `json:"investigationMode"`
	QuarantineFiles        bool   `json:"quarantineFiles"`
	QuarantineDirectory    string `json:"quarantineDirectory"`
}

// WhitelistVM represents whitelist configuration
type WhitelistVM struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths"`
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
