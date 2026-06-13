package config

import (
	"log"
	"os"
	"strconv"
)

// ApplyEnvOverrides overlays PROCSNIPER_* environment variables onto a loaded ResponseConfig,
// sitting between the JSON layer and CLI flags in the precedence chain (Phase 2 e: compiled
// defaults -> JSON file -> env -> CLI, last-wins). Only a focused set of security-relevant
// tunables is overridable. Invalid values are ignored (and logged) so a typo can never silently
// disable detection or collapse a threshold.
func ApplyEnvOverrides(rc *ResponseConfig) {
	if rc == nil {
		return
	}

	if v := os.Getenv("PROCSNIPER_DETECTION_MODE"); v != "" {
		if IsValidDetectionMode(v) {
			rc.ResponseSettings.DetectionMode = v
		} else {
			log.Printf("[CONFIG] ignoring invalid PROCSNIPER_DETECTION_MODE=%q (want rules_only|hybrid|ml_only)", v)
		}
	}

	if v := os.Getenv("PROCSNIPER_CANARY_RESPONSE"); v != "" {
		if IsValidCanaryResponse(v) {
			rc.ResponseSettings.CanaryResponseAction = v
		} else {
			log.Printf("[CONFIG] ignoring invalid PROCSNIPER_CANARY_RESPONSE=%q (want terminate|suspend|alert_only)", v)
		}
	}

	if v, ok := envBool("PROCSNIPER_AUTO_TERMINATE"); ok {
		rc.ResponseSettings.AutoTerminateEnabled = v
	}
	if v, ok := envBool("PROCSNIPER_INVESTIGATION_MODE"); ok {
		rc.ResponseSettings.InvestigationMode = v
	}

	if v, ok := envNonNegInt("PROCSNIPER_CRITICAL_SCORE_THRESHOLD"); ok {
		rc.ResponseSettings.CriticalScoreThreshold = v
	}
	if v, ok := envNonNegInt("PROCSNIPER_IO_VELOCITY_CRITICAL"); ok {
		rc.DetectionThresholds.IOVelocityThresholdPerMinute = v
	}
}

// envBool reads key as a bool override; ok is false when unset or malformed.
func envBool(key string) (value, ok bool) {
	s := os.Getenv(key)
	if s == "" {
		return false, false
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		log.Printf("[CONFIG] ignoring invalid %s=%q (want true/false)", key, s)
		return false, false
	}
	return b, true
}

// envNonNegInt reads key as a non-negative int override; ok is false when unset or invalid.
func envNonNegInt(key string) (value int, ok bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		log.Printf("[CONFIG] ignoring invalid %s=%q (want non-negative integer)", key, s)
		return 0, false
	}
	return n, true
}
