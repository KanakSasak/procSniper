package usecase

import (
	"fmt"
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

// commandAnalyzer inspects process-create command lines for ransomware-prep techniques:
// system-info reconnaissance, shadow-copy deletion / recovery disable (instant-kill), and
// other suspicious command patterns. Migrated verbatim from
// DetectionService.ProcessProcessCreate (Phase 6) — the inline counters-map lock blocks
// became setMLCounter calls; behavior is otherwise unchanged.
type commandAnalyzer struct{ sink analyzerSink }

var _ eventAnalyzer = commandAnalyzer{}

func (a commandAnalyzer) analyze(event *domain.MonitorEvent) {
	if a.sink.isTrustedProcess(event.Image) {
		return
	}

	cmdLine := strings.ToLower(event.CommandLine)
	imageLower := strings.ToLower(event.Image)

	// ML feature tracking: detect system info reconnaissance commands
	isSystemInfoCmd := strings.Contains(cmdLine, "systeminfo") || strings.Contains(cmdLine, "whoami") ||
		strings.Contains(cmdLine, "hostname") || strings.Contains(cmdLine, "ipconfig") ||
		strings.Contains(cmdLine, "net user") || strings.Contains(cmdLine, "net localgroup")
	if isSystemInfoCmd {
		a.sink.setMLCounter(event.ProcessGuid, func(c *ProcessFileCounters) {
			c.SystemInfoHit = true
		})
	}

	// CRITICAL: Detect shadow copy deletion attempts (common ransomware technique)
	// Instant termination - this is a clear indicator of ransomware preparation
	isShadowCopyDeletion := false
	if strings.Contains(imageLower, "vssadmin.exe") && strings.Contains(cmdLine, "delete shadows") {
		isShadowCopyDeletion = true
	} else if strings.Contains(imageLower, "wmic.exe") && strings.Contains(cmdLine, "shadowcopy delete") {
		isShadowCopyDeletion = true
	} else if strings.Contains(imageLower, "bcdedit.exe") && (strings.Contains(cmdLine, "recoveryenabled no") || strings.Contains(cmdLine, "bootstatuspolicy ignoreallfailures")) {
		isShadowCopyDeletion = true
	}

	if isShadowCopyDeletion {
		a.sink.setMLCounter(event.ProcessGuid, func(c *ProcessFileCounters) {
			c.ShadowCopyDeleteHit = true
		})

		log.Printf("[DETECTION] 🚨 CRITICAL: Shadow copy deletion/recovery disable detected!")
		log.Printf("[DETECTION] 🚨 Command: %s", event.CommandLine)
		log.Printf("[DETECTION] 🚨 Process: %s (PID: %d)", event.Image, event.ProcessID)

		// Add indicator with MASSIVE score to guarantee immediate termination
		indicator := domain.Indicator{
			Type:        domain.IndicatorShadowCopyDeletion,
			Severity:    domain.ThreatCritical,
			Points:      100, // Override - guarantee immediate termination
			Description: fmt.Sprintf("INSTANT KILL: Shadow copy deletion/recovery disable attempt detected - %s", event.CommandLine),
			Timestamp:   event.Timestamp,
			Evidence: map[string]string{
				"command": event.CommandLine,
				"process": event.Image,
				"pid":     fmt.Sprintf("%d", event.ProcessID),
				"instant": "true",
			},
		}

		score := a.sink.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
		log.Printf("[DETECTION] 🔴 SHADOW COPY DELETION - IMMEDIATE TERMINATION TRIGGERED (Score: %d)", score)

		// Propagate shadow_copy_delete to parent process (ransomware spawns vssadmin/wmic)
		a.sink.propagateMLFlagToParent(event, true, false, false)

		// Force immediate evaluation and alert
		a.sink.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
		return
	}

	// Check for other suspicious command patterns
	for pattern, description := range domain.SuspiciousCommandPatterns {
		if strings.Contains(cmdLine, strings.ToLower(pattern)) {
			var indicatorType domain.IndicatorType

			if strings.Contains(description, "Shadow copy") {
				indicatorType = domain.IndicatorShadowCopyDeletion
			} else if strings.Contains(description, "Recovery") {
				indicatorType = domain.IndicatorRecoveryDisable
			} else {
				indicatorType = domain.IndicatorLSASSAccess
			}

			a.sink.setMLCounter(event.ProcessGuid, func(c *ProcessFileCounters) {
				if indicatorType == domain.IndicatorShadowCopyDeletion {
					c.ShadowCopyDeleteHit = true
				}
				if indicatorType == domain.IndicatorLSASSAccess {
					c.LSASSAccessHit = true
				}
			})

			indicator := domain.Indicator{
				Type:        indicatorType,
				Severity:    domain.ThreatCritical,
				Points:      domain.IndicatorScores[indicatorType],
				Description: description,
				Timestamp:   event.Timestamp,
				Evidence: map[string]string{
					"command": event.CommandLine,
					"pattern": pattern,
				},
			}

			score := a.sink.addRuleIndicator(event.ProcessGuid, event.Image, event.ProcessID, indicator)
			log.Printf("[DETECTION] Suspicious command: %s (Score: %d)", description, score)

			// Propagate suspicious command flags to parent (ransomware spawns child for these)
			a.sink.propagateMLFlagToParent(event,
				indicatorType == domain.IndicatorShadowCopyDeletion,
				false,
				indicatorType == domain.IndicatorLSASSAccess,
			)
		}
	}

	// Propagate system_info flag to parent process (ransomware spawns cmd.exe /c systeminfo)
	if isSystemInfoCmd {
		a.sink.propagateMLFlagToParent(event, false, true, false)
	}

	a.sink.evaluateAndAlert(event.ProcessGuid, event.Image, event.ProcessID)
}
