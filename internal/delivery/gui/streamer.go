//go:build windows

package gui

import (
	"time"

	"procSniper/internal/delivery/gui/events"
	"procSniper/internal/delivery/gui/logger"
	"procSniper/internal/delivery/gui/models"
	"procSniper/internal/domain"
)

// streamer owns the GUI's background streaming goroutines (dashboard stats, alerts, logs),
// decoupling them from App so the adapter stays thin. The protection-lifecycle streams (stats +
// alerts) share one stop channel; the log stream has its own independent lifecycle.
type streamer struct {
	emitter    *events.Emitter
	logCapture *logger.LogCapture

	stopStats chan struct{}
	stopLogs  chan struct{}
}

func newStreamer(emitter *events.Emitter, logCapture *logger.LogCapture) *streamer {
	return &streamer{emitter: emitter, logCapture: logCapture}
}

// startProtectionStreams launches the 2s dashboard-stats poll + the alert stream. The data sources
// are passed in (the alert channel, the syslog-forward, and the dashboard/threats snapshot funcs)
// so the streamer stays free of the App's component graph.
func (s *streamer) startProtectionStreams(
	alertChan <-chan *domain.Alert,
	forwardSyslog func(*domain.Alert),
	dashboard func() models.DashboardStats,
	threats func() []models.ThreatViewModel,
) {
	s.stopStats = make(chan struct{})
	go s.runStats(dashboard, threats)
	go s.runAlerts(alertChan, forwardSyslog)
}

// stopProtectionStreams stops the stats + alert goroutines.
func (s *streamer) stopProtectionStreams() {
	if s.stopStats != nil {
		close(s.stopStats)
	}
}

func (s *streamer) runStats(dashboard func() models.DashboardStats, threats func() []models.ThreatViewModel) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopStats:
			return
		case <-ticker.C:
			s.emitter.EmitStatsUpdate(dashboard())
			s.emitter.EmitThreatUpdate(threats())
		}
	}
}

func (s *streamer) runAlerts(alertChan <-chan *domain.Alert, forwardSyslog func(*domain.Alert)) {
	if alertChan == nil {
		return
	}
	for {
		select {
		case <-s.stopStats:
			return
		case alert, ok := <-alertChan:
			if !ok {
				return
			}
			s.emitter.EmitAlert(models.AlertFromDomain(alert))
			// Alerts are split between the orchestrator and this GUI stream; forward to syslog here.
			if forwardSyslog != nil {
				forwardSyslog(alert)
			}
		}
	}
}

// startLogStream launches the log-subscription stream (independent of protection lifecycle).
func (s *streamer) startLogStream() {
	s.stopLogs = make(chan struct{})
	go s.runLogs()
}

// stopLogStream stops the log stream; safe to call when already stopped or never started.
func (s *streamer) stopLogStream() {
	if s.stopLogs == nil {
		return
	}
	select {
	case <-s.stopLogs:
		// already closed
	default:
		close(s.stopLogs)
	}
}

func (s *streamer) runLogs() {
	logChan := s.logCapture.Subscribe()
	defer s.logCapture.Unsubscribe(logChan)

	for {
		select {
		case <-s.stopLogs:
			return
		case entry, ok := <-logChan:
			if !ok {
				return
			}
			s.emitter.EmitLogEntry(entry)
		}
	}
}
