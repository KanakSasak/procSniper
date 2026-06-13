package config

import "fmt"

// Canonical detection modes and canary response actions — validated in one place (Phase 2 d)
// instead of being re-checked as string literals across the CLI arg parser and the GUI.
const (
	DetectionModeRulesOnly = "rules_only"
	DetectionModeHybrid    = "hybrid"
	DetectionModeMLOnly    = "ml_only"

	CanaryResponseTerminate = "terminate"
	CanaryResponseSuspend   = "suspend"
	CanaryResponseAlertOnly = "alert_only"
)

// IsValidDetectionMode reports whether mode is a recognized detection mode.
func IsValidDetectionMode(mode string) bool {
	switch mode {
	case DetectionModeRulesOnly, DetectionModeHybrid, DetectionModeMLOnly:
		return true
	default:
		return false
	}
}

// DetectionModeRequiresML reports whether a mode needs a loaded ML model.
func DetectionModeRequiresML(mode string) bool {
	return mode == DetectionModeHybrid || mode == DetectionModeMLOnly
}

// IsValidCanaryResponse reports whether action is a recognized canary response action.
func IsValidCanaryResponse(action string) bool {
	switch action {
	case CanaryResponseTerminate, CanaryResponseSuspend, CanaryResponseAlertOnly:
		return true
	default:
		return false
	}
}

// ProtectOptions holds the parsed `protect` command options. It centralizes the validation and
// default-resolution that were duplicated across the CLI os.Args walk and the GUI (Phase 2 d),
// so adding/renaming an option no longer means editing three places.
type ProtectOptions struct {
	MLModelPath     string
	MLConfidence    float64
	MLMinIndicators int
	DetectionMode   string
	CanaryResponse  string
}

// DefaultProtectOptions returns the baseline option values (before config/flags are applied).
func DefaultProtectOptions() ProtectOptions {
	return ProtectOptions{
		MLConfidence:    0.75,
		MLMinIndicators: 4,
	}
}

// Resolve fills an empty DetectionMode/CanaryResponse from the response config and then the
// hard-coded fallbacks, matching the prior CLI default logic: an ML model present with no
// explicit mode defaults to ml_only; otherwise the config's mode, otherwise rules_only.
func (o *ProtectOptions) Resolve(rc *ResponseConfig) {
	if o.DetectionMode == "" {
		switch {
		case o.MLModelPath != "":
			o.DetectionMode = DetectionModeMLOnly
		case rc != nil && rc.ResponseSettings.DetectionMode != "":
			o.DetectionMode = rc.ResponseSettings.DetectionMode
		default:
			o.DetectionMode = DetectionModeRulesOnly
		}
	}
	if o.CanaryResponse == "" {
		if rc != nil && rc.ResponseSettings.CanaryResponseAction != "" {
			o.CanaryResponse = rc.ResponseSettings.CanaryResponseAction
		} else {
			o.CanaryResponse = CanaryResponseTerminate
		}
	}
}

// Validate checks ranges, enums, and the cross-field rule that hybrid/ml_only require an ML
// model. It returns a user-facing error (nil when valid). Call after Resolve.
func (o ProtectOptions) Validate() error {
	if o.MLConfidence < 0 || o.MLConfidence > 1 {
		return fmt.Errorf("--ml-confidence must be between 0.0 and 1.0")
	}
	if o.MLMinIndicators < 1 {
		return fmt.Errorf("--ml-min-indicators must be a positive integer")
	}
	if !IsValidDetectionMode(o.DetectionMode) {
		return fmt.Errorf("--detection-mode must be rules_only, hybrid, or ml_only")
	}
	if !IsValidCanaryResponse(o.CanaryResponse) {
		return fmt.Errorf("--canary-response must be terminate, suspend, or alert_only")
	}
	if DetectionModeRequiresML(o.DetectionMode) && o.MLModelPath == "" {
		return fmt.Errorf("--detection-mode %s requires --ml <model_path>", o.DetectionMode)
	}
	return nil
}
