package usecase

import (
	"log"
	"strings"

	"procSniper/internal/domain"
)

// eventAnalyzer inspects a kernel MonitorEvent and performs one detection concern,
// emitting through the injected analyzerSink. This is the seam for the Phase 6
// "Analyzer strategy": detectors are migrated out of the DetectionService.Process*
// god-methods one at a time, each becoming a small, independently-readable analyzer.
type eventAnalyzer interface {
	analyze(event *domain.MonitorEvent)
}

// analyzerSink is what analyzers use to read trusted-process state, mutate per-process ML
// feature flags, raise indicators, propagate flags to the parent, and trigger evaluation.
// Implemented by *DetectionService (all methods already exist except setMLCounter).
type analyzerSink interface {
	isTrustedProcess(image string) bool
	setMLCounter(processGuid string, set func(*ProcessFileCounters))
	addRuleIndicator(processGuid, image string, pid int, indicator domain.Indicator) int
	propagateMLFlagToParent(event *domain.MonitorEvent, shadowCopy, systemInfo, lsassAccess bool)
	evaluateAndAlert(processGuid, image string, pid int)
}

// lsassAnalyzer flags a non-trusted process opening LSASS memory (credential dumping).
// Migrated verbatim from DetectionService.ProcessLSASSAccess (Phase 6).
type lsassAnalyzer struct{ sink analyzerSink }

var _ eventAnalyzer = lsassAnalyzer{}

func (a lsassAnalyzer) analyze(event *domain.MonitorEvent) {
	if a.sink.isTrustedProcess(event.Image) {
		return
	}

	if !strings.Contains(strings.ToLower(event.TargetImage), "lsass.exe") {
		return
	}

	a.sink.setMLCounter(event.ProcessGuid, func(c *ProcessFileCounters) {
		c.LSASSAccessHit = true
	})

	indicator := domain.Indicator{
		Type:        domain.IndicatorLSASSAccess,
		Severity:    domain.ThreatCritical,
		Points:      domain.IndicatorScores[domain.IndicatorLSASSAccess],
		Description: "LSASS memory access detected",
		Timestamp:   event.Timestamp,
		Evidence: map[string]string{
			"granted_access": event.GrantedAccess,
			"target":         event.TargetImage,
		},
	}

	score := a.sink.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
	log.Printf("[DETECTION] LSASS access: %s (Access: %s, Score: %d)",
		event.Image, event.GrantedAccess, score)

	// Propagate LSASS access to parent (ransomware may spawn child for credential dumping).
	a.sink.propagateMLFlagToParent(event, false, false, true)

	a.sink.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}
