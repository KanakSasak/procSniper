//go:build windows

package events

import (
	"context"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"procSniper/internal/delivery/gui/logger"
	"procSniper/internal/delivery/gui/models"
)

// Event names for frontend subscription
const (
	EventAlertNew      = "alert:new"
	EventStatsUpdate   = "stats:update"
	EventThreatLevel   = "threat:level"
	EventThreatUpdate  = "threat:update"
	EventLogEntry      = "log:entry"
	EventMLPrediction  = "ml:prediction"
)

// Emitter handles event emission to the frontend
type Emitter struct {
	ctx context.Context
}

// NewEmitter creates a new event emitter
func NewEmitter(ctx context.Context) *Emitter {
	return &Emitter{ctx: ctx}
}

// EmitAlert sends a new alert to the frontend
func (e *Emitter) EmitAlert(alert models.AlertViewModel) {
	runtime.EventsEmit(e.ctx, EventAlertNew, alert)
}

// EmitStatsUpdate sends updated statistics to the frontend
func (e *Emitter) EmitStatsUpdate(stats models.DashboardStats) {
	runtime.EventsEmit(e.ctx, EventStatsUpdate, stats)
}

// EmitThreatLevelChange sends threat level change notification
func (e *Emitter) EmitThreatLevelChange(level string) {
	runtime.EventsEmit(e.ctx, EventThreatLevel, level)
}

// EmitThreatUpdate sends updated threat list to the frontend
func (e *Emitter) EmitThreatUpdate(threats []models.ThreatViewModel) {
	runtime.EventsEmit(e.ctx, EventThreatUpdate, threats)
}

// EmitLogEntry sends a log entry to the frontend
func (e *Emitter) EmitLogEntry(entry logger.LogEntry) {
	runtime.EventsEmit(e.ctx, EventLogEntry, entry)
}

// EmitMLPrediction sends an ML prediction result to the frontend
func (e *Emitter) EmitMLPrediction(pred models.MLPredictionVM) {
	runtime.EventsEmit(e.ctx, EventMLPrediction, pred)
}
