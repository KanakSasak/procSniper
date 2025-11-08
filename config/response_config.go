package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DetectionThresholds defines file count thresholds for triggering indicators
type DetectionThresholds struct {
	HighEntropyFileThreshold             int    `json:"high_entropy_file_threshold"`
	RansomwareExtensionFileThreshold     int    `json:"ransomware_extension_file_threshold"`
	CombinedEntropyAndExtensionThreshold int    `json:"combined_entropy_and_extension_threshold"`
	IOVelocityThresholdPerMinute         int    `json:"io_velocity_threshold_per_minute"`
	Note                                 string `json:"note"`
}

// ResponseConfig holds ransomware detection and response configuration
type ResponseConfig struct {
	Version     string `json:"version"`
	LastUpdated string `json:"last_updated"`
	Description string `json:"description"`

	RansomwareExtensions []string            `json:"ransomware_extensions"`
	DetectionThresholds  DetectionThresholds `json:"detection_thresholds"`
	ResponseSettings     ResponseSetting     `json:"response_settings"`
	Whitelist            WhitelistConfig     `json:"whitelist"`
	AlertSettings        AlertConfig         `json:"alert_settings"`
	RansomNoteFilenames  []string            `json:"ransom_note_filenames"`
	Notes                []string            `json:"notes"`
}

// ResponseSetting defines automated response behavior
type ResponseSetting struct {
	AutoTerminateEnabled      bool   `json:"auto_terminate_enabled"`
	ImmediateResponse         bool   `json:"immediate_response"`
	TerminateOnExtensionMatch bool   `json:"terminate_on_extension_match"`
	TerminateOnCriticalScore  bool   `json:"terminate_on_critical_score"`
	CriticalScoreThreshold    int    `json:"critical_score_threshold"`
	QuarantineFiles           bool   `json:"quarantine_files"`
	QuarantineDirectory       string `json:"quarantine_directory"`
	SuspendBeforeTerminate    bool   `json:"suspend_before_terminate"`
	InvestigationMode         bool   `json:"investigation_mode"`
}

// WhitelistConfig defines processes/paths exempt from auto-response
type WhitelistConfig struct {
	Enabled   bool     `json:"enabled"`
	Processes []string `json:"processes"`
	Paths     []string `json:"paths"`
	Note      string   `json:"note"`
}

// AlertConfig defines alerting behavior
type AlertConfig struct {
	LogFile         string `json:"log_file"`
	SendEmailAlerts bool   `json:"send_email_alerts"`
	SendSyslog      bool   `json:"send_syslog"`
	SyslogServer    string `json:"syslog_server"`
	VerboseLogging  bool   `json:"verbose_logging"`
}

// LoadResponseConfig loads ransomware extension and response configuration
func LoadResponseConfig(configPath string) (*ResponseConfig, error) {
	// Default path if not specified
	if configPath == "" {
		configPath = "config/ransomware_extensions.json"
	}

	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read response config: %w", err)
	}

	var config ResponseConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse response config: %w", err)
	}

	// Normalize extensions to lowercase
	for i := range config.RansomwareExtensions {
		config.RansomwareExtensions[i] = strings.ToLower(config.RansomwareExtensions[i])
	}

	return &config, nil
}

// IsRansomwareExtension checks if file extension matches ransomware pattern
func (rc *ResponseConfig) IsRansomwareExtension(extension string) bool {
	extLower := strings.ToLower(extension)
	for _, ransomExt := range rc.RansomwareExtensions {
		if extLower == ransomExt {
			return true
		}
	}
	return false
}

// IsWhitelisted checks if a path is whitelisted
func (rc *ResponseConfig) IsWhitelisted(path string) bool {
	if !rc.Whitelist.Enabled {
		return false
	}

	pathLower := strings.ToLower(path)
	for _, whitelistPath := range rc.Whitelist.Paths {
		if strings.HasPrefix(pathLower, strings.ToLower(whitelistPath)) {
			return true
		}
	}

	return false
}

// ShouldAutoTerminate determines if auto-terminate should be triggered
func (rc *ResponseConfig) ShouldAutoTerminate(score int, extensionMatch bool, path string) bool {
	// Investigation mode disables auto-terminate
	if rc.ResponseSettings.InvestigationMode {
		return false
	}

	// Check whitelist
	if rc.IsWhitelisted(path) {
		return false
	}

	// Auto-terminate disabled globally
	if !rc.ResponseSettings.AutoTerminateEnabled {
		return false
	}

	// Immediate response on extension match
	if rc.ResponseSettings.TerminateOnExtensionMatch && extensionMatch {
		return true
	}

	// Auto-terminate on critical score
	if rc.ResponseSettings.TerminateOnCriticalScore && score >= rc.ResponseSettings.CriticalScoreThreshold {
		return true
	}

	return false
}

// GetQuarantineDirectory returns the quarantine directory path
func (rc *ResponseConfig) GetQuarantineDirectory() string {
	if rc.ResponseSettings.QuarantineDirectory != "" {
		return rc.ResponseSettings.QuarantineDirectory
	}
	return "C:\\ProgramData\\procSniper\\quarantine"
}

// UpdateExtensions adds new ransomware extensions (for runtime updates)
func (rc *ResponseConfig) UpdateExtensions(newExtensions []string) {
	for _, ext := range newExtensions {
		extLower := strings.ToLower(ext)
		// Check if already exists
		exists := false
		for _, existing := range rc.RansomwareExtensions {
			if existing == extLower {
				exists = true
				break
			}
		}
		if !exists {
			rc.RansomwareExtensions = append(rc.RansomwareExtensions, extLower)
		}
	}
}

// SaveConfig saves the configuration back to file
func (rc *ResponseConfig) SaveConfig(configPath string) error {
	data, err := json.MarshalIndent(rc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
