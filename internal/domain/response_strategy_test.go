package domain

import "testing"

func TestStrategyForCanaryAction(t *testing.T) {
	cases := map[string]ResponseStrategy{
		"suspend":    ResponseStrategySuspend,
		"terminate":  ResponseStrategyTerminate,
		"alert_only": ResponseStrategyTerminate, // not acted on (AutoRespond=false), so terminate-default is harmless
		"":           ResponseStrategyTerminate,
		"bogus":      ResponseStrategyTerminate,
	}
	for action, want := range cases {
		if got := StrategyForCanaryAction(action); got != want {
			t.Errorf("StrategyForCanaryAction(%q) = %q, want %q", action, got, want)
		}
	}
}

func TestAlert_IsCanaryCompromise(t *testing.T) {
	if (&Alert{Indicators: []Indicator{{Type: IndicatorHighEntropy}}}).IsCanaryCompromise() {
		t.Error("non-canary indicators should not be a canary compromise")
	}
	if !(&Alert{Indicators: []Indicator{{Type: IndicatorCanaryCompromised}}}).IsCanaryCompromise() {
		t.Error("IndicatorCanaryCompromised should be a canary compromise")
	}
	// alertCompromised uses synthesized CANARY_<type> indicator types.
	if !(&Alert{Indicators: []Indicator{{Type: IndicatorType("CANARY_DELETED")}}}).IsCanaryCompromise() {
		t.Error("CANARY_-prefixed indicator type should be a canary compromise")
	}
	if (&Alert{}).IsCanaryCompromise() {
		t.Error("no indicators should not be a canary compromise")
	}
}
