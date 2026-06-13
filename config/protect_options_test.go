package config

import "testing"

func TestProtectOptions_Resolve(t *testing.T) {
	// ML model present, no explicit mode -> ml_only.
	o := ProtectOptions{MLModelPath: "model.onnx"}
	o.Resolve(nil)
	if o.DetectionMode != DetectionModeMLOnly {
		t.Errorf("with ML, no mode -> %q, want ml_only", o.DetectionMode)
	}
	if o.CanaryResponse != CanaryResponseTerminate {
		t.Errorf("default canary -> %q, want terminate", o.CanaryResponse)
	}

	// No ML, no config -> rules_only.
	o = ProtectOptions{}
	o.Resolve(nil)
	if o.DetectionMode != DetectionModeRulesOnly {
		t.Errorf("no ML, no config -> %q, want rules_only", o.DetectionMode)
	}

	// Config provides the defaults when flags are empty and no ML model forces ml_only.
	rc := &ResponseConfig{}
	rc.ResponseSettings.DetectionMode = DetectionModeHybrid
	rc.ResponseSettings.CanaryResponseAction = CanaryResponseSuspend
	o = ProtectOptions{}
	o.Resolve(rc)
	if o.DetectionMode != DetectionModeHybrid {
		t.Errorf("config mode -> %q, want hybrid", o.DetectionMode)
	}
	if o.CanaryResponse != CanaryResponseSuspend {
		t.Errorf("config canary -> %q, want suspend", o.CanaryResponse)
	}

	// An ML model with no explicit mode wins over the config's mode (-> ml_only).
	o = ProtectOptions{MLModelPath: "m.onnx"}
	o.Resolve(rc)
	if o.DetectionMode != DetectionModeMLOnly {
		t.Errorf("ML present overrides config mode -> %q, want ml_only", o.DetectionMode)
	}

	// Explicit flags win over config.
	o = ProtectOptions{DetectionMode: DetectionModeRulesOnly, CanaryResponse: CanaryResponseAlertOnly}
	o.Resolve(rc)
	if o.DetectionMode != DetectionModeRulesOnly || o.CanaryResponse != CanaryResponseAlertOnly {
		t.Errorf("explicit flags overridden: %+v", o)
	}
}

func TestProtectOptions_Validate(t *testing.T) {
	valid := ProtectOptions{MLConfidence: 0.75, MLMinIndicators: 4, DetectionMode: DetectionModeRulesOnly, CanaryResponse: CanaryResponseTerminate}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid options rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*ProtectOptions)
	}{
		{"confidence too high", func(o *ProtectOptions) { o.MLConfidence = 1.5 }},
		{"confidence negative", func(o *ProtectOptions) { o.MLConfidence = -0.1 }},
		{"min indicators zero", func(o *ProtectOptions) { o.MLMinIndicators = 0 }},
		{"bad detection mode", func(o *ProtectOptions) { o.DetectionMode = "bogus" }},
		{"bad canary response", func(o *ProtectOptions) { o.CanaryResponse = "freeze" }},
		{"hybrid without ML", func(o *ProtectOptions) { o.DetectionMode = DetectionModeHybrid; o.MLModelPath = "" }},
		{"ml_only without ML", func(o *ProtectOptions) { o.DetectionMode = DetectionModeMLOnly; o.MLModelPath = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := valid
			tc.mut(&o)
			if err := o.Validate(); err == nil {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}

	// hybrid/ml_only WITH an ML model is valid.
	ml := ProtectOptions{MLConfidence: 0.9, MLMinIndicators: 2, DetectionMode: DetectionModeMLOnly, CanaryResponse: CanaryResponseSuspend, MLModelPath: "m.onnx"}
	if err := ml.Validate(); err != nil {
		t.Errorf("ml_only with model rejected: %v", err)
	}
}
