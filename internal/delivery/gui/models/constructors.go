//go:build windows

package models

import (
	"path/filepath"
	"strings"
	"time"

	"procSniper/config"
	"procSniper/internal/domain"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

// MLPredictionVMFromActivity converts an ML inference activity into its frontend view model,
// preferring the nested Prediction's fields when present and defaulting a zero timestamp to now.
func MLPredictionVMFromActivity(activity *domain.MLInferenceActivity) MLPredictionVM {
	processName := "UNKNOWN"
	processID := activity.ProcessID
	label := "unknown"
	confidence := 0.0
	probabilities := [3]float64{}
	timestamp := activity.Timestamp

	if strings.TrimSpace(activity.Image) != "" {
		processName = filepath.Base(activity.Image)
	}

	if pred := activity.Prediction; pred != nil {
		if strings.TrimSpace(pred.Image) != "" {
			processName = filepath.Base(pred.Image)
		}
		processID = pred.ProcessID
		if strings.TrimSpace(pred.LabelName) != "" {
			label = pred.LabelName
		}
		confidence = pred.Confidence
		probabilities = pred.Probabilities
		if timestamp.IsZero() {
			timestamp = pred.Timestamp
		}
	}

	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	return MLPredictionVM{
		ProcessName:         processName,
		ProcessID:           processID,
		Label:               label,
		Confidence:          confidence,
		Probabilities:       probabilities,
		Stage:               activity.Stage,
		Reason:              activity.Reason,
		Decision:            activity.Decision,
		DecisionCategory:    activity.DecisionCategory,
		DecisionScore:       activity.DecisionScore,
		DecisionAutoRespond: activity.DecisionAutoRespond,
		Threshold:           activity.Threshold,
		ModeEnabled:         activity.ModeEnabled,
		PredictorReady:      activity.PredictorReady,
		Error:               activity.Error,
		Timestamp:           timestamp.Format(time.RFC3339),
	}
}

// EntropyStatsVMFromStats converts entropy tracker stats to its view model.
func EntropyStatsVMFromStats(s domain.EntropyStats) EntropyStatsVM {
	return EntropyStatsVM{
		TrackedFiles:         s.TrackedFiles,
		ModifiedFiles:        s.ModifiedFiles,
		SignificantIncreases: s.SignificantIncreases,
	}
}

// DashboardStatsFromStats builds the dashboard view model from the typed component snapshots.
// ProtectionStatus is set to "Active" (callers use this only while protecting). ActiveThreatsCount
// and HighIOProcessCount are filled by the caller — they are read directly off the detection
// service rather than from these snapshots.
func DashboardStatsFromStats(etw infrastructure.ETWConsumerStats, orch usecase.OrchestrationStats, canaryCount int, entropy domain.EntropyStats) DashboardStats {
	return DashboardStats{
		ProtectionStatus:     "Active",
		ETWConnected:         etw.Running,
		WorkerQueueDepth:     etw.ChannelLength,
		AlertsProcessed:      orch.AlertsProcessed,
		ProcessesTerminated:  orch.ProcessesTerminated,
		FilesQuarantined:     orch.FilesQuarantined,
		CanaryFilesCount:     canaryCount,
		AutoResponsesBlocked: orch.AutoResponsesBlocked,
		ETWDiagnostics: ETWDiagnosticsVM{
			EventsReceived:          etw.EventsReceived,
			EventsDropped:           etw.EventsDropped,
			EventsSuppressedDeadPID: etw.EventsSuppressedDeadPID,
			WorkerPoolSize:          etw.WorkerPoolSize,
			ChannelCapacity:         etw.ChannelCapacity,
			ChannelLength:           etw.ChannelLength,
		},
		EntropyStats: EntropyStatsVMFromStats(entropy),
	}
}

// ConfigViewModelFromResponseConfig flattens the response config into the frontend view model.
func ConfigViewModelFromResponseConfig(rc *config.ResponseConfig) ConfigViewModel {
	if rc == nil {
		return ConfigViewModel{}
	}
	return ConfigViewModel{
		Version:     rc.Version,
		LastUpdated: rc.LastUpdated,
		DetectionThresholds: DetectionThresholdsVM{
			HighEntropyFileThreshold:             rc.DetectionThresholds.HighEntropyFileThreshold,
			RansomwareExtensionFileThreshold:     rc.DetectionThresholds.RansomwareExtensionFileThreshold,
			RansomwareExtensionRenameThreshold:   rc.DetectionThresholds.RansomwareExtensionRenameThreshold,
			CombinedEntropyAndExtensionThreshold: rc.DetectionThresholds.CombinedEntropyAndExtensionThreshold,
			IOVelocityThresholdPerMinute:         rc.DetectionThresholds.IOVelocityThresholdPerMinute,
		},
		ResponseSettings: ResponseSettingsVM{
			AutoTerminateEnabled:      rc.ResponseSettings.AutoTerminateEnabled,
			CriticalScoreThreshold:    rc.ResponseSettings.CriticalScoreThreshold,
			InvestigationMode:         rc.ResponseSettings.InvestigationMode,
			QuarantineFiles:           rc.ResponseSettings.QuarantineFiles,
			QuarantineDirectory:       rc.ResponseSettings.QuarantineDirectory,
			ImmediateResponse:         rc.ResponseSettings.ImmediateResponse,
			TerminateOnExtensionMatch: rc.ResponseSettings.TerminateOnExtensionMatch,
			SuspendBeforeTerminate:    rc.ResponseSettings.SuspendBeforeTerminate,
			DetectionMode:             rc.ResponseSettings.DetectionMode,
			CanaryResponseAction:      rc.ResponseSettings.CanaryResponseAction,
		},
		Whitelist: WhitelistVM{
			Enabled:   rc.Whitelist.Enabled,
			Paths:     rc.Whitelist.Paths,
			Processes: rc.Whitelist.Processes,
		},
		RansomwareExtensions: rc.RansomwareExtensions,
	}
}

// ApplyToResponseConfig writes the editable view-model fields back onto the response config.
func (cfg ConfigViewModel) ApplyToResponseConfig(rc *config.ResponseConfig) {
	rc.DetectionThresholds.HighEntropyFileThreshold = cfg.DetectionThresholds.HighEntropyFileThreshold
	rc.DetectionThresholds.RansomwareExtensionFileThreshold = cfg.DetectionThresholds.RansomwareExtensionFileThreshold
	rc.DetectionThresholds.RansomwareExtensionRenameThreshold = cfg.DetectionThresholds.RansomwareExtensionRenameThreshold
	rc.DetectionThresholds.CombinedEntropyAndExtensionThreshold = cfg.DetectionThresholds.CombinedEntropyAndExtensionThreshold
	rc.DetectionThresholds.IOVelocityThresholdPerMinute = cfg.DetectionThresholds.IOVelocityThresholdPerMinute

	rc.ResponseSettings.AutoTerminateEnabled = cfg.ResponseSettings.AutoTerminateEnabled
	rc.ResponseSettings.CriticalScoreThreshold = cfg.ResponseSettings.CriticalScoreThreshold
	rc.ResponseSettings.InvestigationMode = cfg.ResponseSettings.InvestigationMode
	rc.ResponseSettings.QuarantineFiles = cfg.ResponseSettings.QuarantineFiles
	rc.ResponseSettings.QuarantineDirectory = cfg.ResponseSettings.QuarantineDirectory
	rc.ResponseSettings.ImmediateResponse = cfg.ResponseSettings.ImmediateResponse
	rc.ResponseSettings.TerminateOnExtensionMatch = cfg.ResponseSettings.TerminateOnExtensionMatch
	rc.ResponseSettings.SuspendBeforeTerminate = cfg.ResponseSettings.SuspendBeforeTerminate
	rc.ResponseSettings.DetectionMode = cfg.ResponseSettings.DetectionMode
	rc.ResponseSettings.CanaryResponseAction = cfg.ResponseSettings.CanaryResponseAction

	rc.Whitelist.Enabled = cfg.Whitelist.Enabled
	rc.Whitelist.Paths = cfg.Whitelist.Paths
	rc.Whitelist.Processes = cfg.Whitelist.Processes

	rc.RansomwareExtensions = cfg.RansomwareExtensions
}
