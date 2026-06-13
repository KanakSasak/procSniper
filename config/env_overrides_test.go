package config

import "testing"

func TestApplyEnvOverrides(t *testing.T) {
	t.Run("valid overrides applied", func(t *testing.T) {
		t.Setenv("PROCSNIPER_DETECTION_MODE", DetectionModeHybrid)
		t.Setenv("PROCSNIPER_CANARY_RESPONSE", CanaryResponseSuspend)
		t.Setenv("PROCSNIPER_AUTO_TERMINATE", "false")
		t.Setenv("PROCSNIPER_INVESTIGATION_MODE", "true")
		t.Setenv("PROCSNIPER_CRITICAL_SCORE_THRESHOLD", "70")
		t.Setenv("PROCSNIPER_IO_VELOCITY_CRITICAL", "150")

		rc := &ResponseConfig{}
		rc.ResponseSettings.AutoTerminateEnabled = true // overridden to false below
		ApplyEnvOverrides(rc)

		if rc.ResponseSettings.DetectionMode != DetectionModeHybrid {
			t.Errorf("DetectionMode = %q, want hybrid", rc.ResponseSettings.DetectionMode)
		}
		if rc.ResponseSettings.CanaryResponseAction != CanaryResponseSuspend {
			t.Errorf("CanaryResponseAction = %q, want suspend", rc.ResponseSettings.CanaryResponseAction)
		}
		if rc.ResponseSettings.AutoTerminateEnabled {
			t.Error("AutoTerminateEnabled should be overridden to false")
		}
		if !rc.ResponseSettings.InvestigationMode {
			t.Error("InvestigationMode should be overridden to true")
		}
		if rc.ResponseSettings.CriticalScoreThreshold != 70 {
			t.Errorf("CriticalScoreThreshold = %d, want 70", rc.ResponseSettings.CriticalScoreThreshold)
		}
		if rc.DetectionThresholds.IOVelocityThresholdPerMinute != 150 {
			t.Errorf("IOVelocityThresholdPerMinute = %d, want 150", rc.DetectionThresholds.IOVelocityThresholdPerMinute)
		}
	})

	t.Run("invalid values ignored, prior kept", func(t *testing.T) {
		t.Setenv("PROCSNIPER_DETECTION_MODE", "bogus")
		t.Setenv("PROCSNIPER_CANARY_RESPONSE", "freeze")
		t.Setenv("PROCSNIPER_AUTO_TERMINATE", "maybe")
		t.Setenv("PROCSNIPER_CRITICAL_SCORE_THRESHOLD", "-5")

		rc := &ResponseConfig{}
		rc.ResponseSettings.DetectionMode = DetectionModeRulesOnly
		rc.ResponseSettings.CanaryResponseAction = CanaryResponseTerminate
		rc.ResponseSettings.AutoTerminateEnabled = true
		rc.ResponseSettings.CriticalScoreThreshold = 49
		ApplyEnvOverrides(rc)

		if rc.ResponseSettings.DetectionMode != DetectionModeRulesOnly {
			t.Error("invalid detection mode should be ignored")
		}
		if rc.ResponseSettings.CanaryResponseAction != CanaryResponseTerminate {
			t.Error("invalid canary response should be ignored")
		}
		if !rc.ResponseSettings.AutoTerminateEnabled {
			t.Error("invalid bool should be ignored (kept true)")
		}
		if rc.ResponseSettings.CriticalScoreThreshold != 49 {
			t.Error("negative int should be ignored (kept 49)")
		}
	})

	t.Run("unset leaves config untouched", func(t *testing.T) {
		rc := &ResponseConfig{}
		rc.ResponseSettings.DetectionMode = DetectionModeMLOnly
		ApplyEnvOverrides(rc)
		if rc.ResponseSettings.DetectionMode != DetectionModeMLOnly {
			t.Error("unset env should leave config untouched")
		}
	})

	t.Run("nil safe", func(t *testing.T) {
		ApplyEnvOverrides(nil) // must not panic
	})
}
