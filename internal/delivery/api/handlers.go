//go:build windows

package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"procSniper/config"
	"procSniper/internal/app"
	"procSniper/internal/domain"
	"procSniper/internal/delivery/gui/models"
	"procSniper/internal/infrastructure"
)

const defaultConfigPath = "config/ransomware_extensions.json"

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func okResult(success bool, msg string) models.OperationResult {
	return models.OperationResult{Success: success, Message: msg}
}

// --- protection lifecycle (mirrors the retired gui.App, re-fronted over HTTP) ---

// StartProtection builds and starts the agent, caches its components, and launches the SSE feeds.
func (s *Server) StartProtection() models.OperationResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isProtecting {
		return okResult(false, "Protection is already running")
	}

	var opts []app.Option
	s.mlMux.RLock()
	if s.mlPredictor != nil {
		opts = append(opts, app.WithMLPredictor(s.mlPredictor, s.mlStatus.Enabled, s.mlStatus.ConfidenceThreshold, s.mlBroadcastCallback()))
	}
	s.mlMux.RUnlock()

	agent, err := app.New(s.cfg, s.responseCfg, opts...)
	if err != nil {
		return okResult(false, err.Error())
	}
	if err := agent.Start(context.Background()); err != nil {
		return okResult(false, err.Error())
	}

	s.agent = agent
	s.detection = agent.DetectionService()
	s.orchestrator = agent.Orchestrator()
	s.etw = agent.ETWConsumer()
	s.isProtecting = true
	s.stopStreams = make(chan struct{})

	go s.runStatsFeed(s.stopStreams)
	go s.runAlertsFeed(s.stopStreams)
	go s.runLogsFeed(s.stopStreams)

	log.Println("[API] protection started")
	return okResult(true, "Protection started")
}

// StopProtection stops the SSE feeds and tears the agent down (WaitGroup join inside agent.Stop).
func (s *Server) StopProtection() models.OperationResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.isProtecting {
		return okResult(false, "Protection is not running")
	}
	if s.stopStreams != nil {
		close(s.stopStreams)
		s.stopStreams = nil
	}
	if s.agent != nil {
		s.agent.Stop()
		s.agent = nil
	}
	s.detection, s.orchestrator, s.etw = nil, nil, nil
	s.isProtecting = false
	log.Println("[API] protection stopped")
	return okResult(true, "Protection stopped")
}

func (s *Server) mlBroadcastCallback() func(*domain.MLInferenceActivity) {
	return func(activity *domain.MLInferenceActivity) {
		if activity == nil {
			return
		}
		s.hub.broadcast("ml:prediction", models.MLPredictionVMFromActivity(activity))
	}
}

// applyMLToRunningDetection forwards the current ML state into the running detection service.
// Caller holds s.mlMux.
func (s *Server) applyMLToRunningDetection() {
	s.mu.Lock()
	det := s.detection
	s.mu.Unlock()
	if det == nil {
		return
	}
	det.SetMLPredictor(s.mlPredictor)
	det.SetMLEnabled(s.mlStatus.Enabled)
	det.SetMLConfidence(s.mlStatus.ConfidenceThreshold)
	det.SetMLPredictionCallback(s.mlBroadcastCallback())
}

// --- view-model snapshots ---

func (s *Server) dashboardStats() models.DashboardStats {
	s.mu.Lock()
	protecting, det, orch, etw := s.isProtecting, s.detection, s.orchestrator, s.etw
	s.mu.Unlock()
	if !protecting || det == nil || orch == nil || etw == nil {
		return models.DashboardStats{ProtectionStatus: "Stopped"}
	}
	st := models.DashboardStatsFromStats(etw.GetStats(), orch.GetStats(), det.GetCanaryStats().TotalCanaries, det.GetEntropyStats())
	st.ActiveThreatsCount = len(det.GetAllThreats())
	st.HighIOProcessCount = det.GetHighIOProcessCount()
	return st
}

func (s *Server) threats() []models.ThreatViewModel {
	s.mu.Lock()
	protecting, det := s.isProtecting, s.detection
	s.mu.Unlock()
	if !protecting || det == nil {
		return []models.ThreatViewModel{}
	}
	dt := det.GetAllThreats()
	out := make([]models.ThreatViewModel, 0, len(dt))
	for _, t := range dt {
		out = append(out, models.ThreatFromDomain(t))
	}
	return out
}

// --- SSE feeds (the streamer.go loops, broadcasting over SSE instead of Wails) ---

func (s *Server) runStatsFeed(stop chan struct{}) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.hub.broadcast("stats:update", s.dashboardStats())
			s.hub.broadcast("threat:update", s.threats())
		}
	}
}

func (s *Server) runAlertsFeed(stop chan struct{}) {
	s.mu.Lock()
	det, orch := s.detection, s.orchestrator
	s.mu.Unlock()
	if det == nil {
		return
	}
	ch := det.GetAlertChannel()
	if ch == nil {
		return
	}
	for {
		select {
		case <-stop:
			return
		case a, ok := <-ch:
			if !ok {
				return
			}
			s.hub.broadcast("alert:new", models.AlertFromDomain(a))
			if orch != nil {
				orch.ForwardAlertToSyslog(a)
			}
		}
	}
}

func (s *Server) runLogsFeed(stop chan struct{}) {
	ch := s.logCapture.Subscribe()
	defer s.logCapture.Unsubscribe(ch)
	for {
		select {
		case <-stop:
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			s.hub.broadcast("log:entry", e)
		}
	}
}

// --- REST handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	protecting := s.isProtecting
	s.mu.Unlock()
	writeJSON(w, map[string]bool{"protecting": protecting})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.dashboardStats())
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.threats())
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.StartProtection())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.StopProtection())
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var vm models.ConfigViewModel
		if err := json.NewDecoder(r.Body).Decode(&vm); err != nil {
			writeJSON(w, okResult(false, "invalid config body: "+err.Error()))
			return
		}
		if s.responseCfg == nil {
			writeJSON(w, okResult(false, "Configuration not loaded"))
			return
		}
		vm.ApplyToResponseConfig(s.responseCfg)
		if err := s.responseCfg.SaveConfig(s.configPath); err != nil {
			writeJSON(w, okResult(false, "Failed to save configuration: "+err.Error()))
			return
		}
		writeJSON(w, okResult(true, "Configuration saved successfully"))
		return
	}
	writeJSON(w, models.ConfigViewModelFromResponseConfig(s.responseCfg))
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.logCapture.Clear()
		writeJSON(w, okResult(true, "logs cleared"))
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, s.logCapture.GetEntries(limit))
}

func (s *Server) handleMLStatus(w http.ResponseWriter, r *http.Request) {
	s.mlMux.RLock()
	st := s.mlStatus
	s.mlMux.RUnlock()
	writeJSON(w, st)
}

func (s *Server) handleMLLoad(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FilePath string `json:"filePath"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.FilePath == "" {
		writeJSON(w, okResult(false, "filePath required"))
		return
	}
	if _, err := os.Stat(req.FilePath); os.IsNotExist(err) {
		writeJSON(w, okResult(false, "Model file not found: "+req.FilePath))
		return
	}
	if strings.ToLower(filepath.Ext(req.FilePath)) != ".onnx" {
		writeJSON(w, okResult(false, "Only ONNX models are supported"))
		return
	}

	s.mlMux.Lock()
	defer s.mlMux.Unlock()
	if s.mlPredictor != nil {
		s.mlPredictor.Close()
		s.mlPredictor = nil
	}
	predictor, err := infrastructure.NewONNXPredictor(req.FilePath, "")
	if err != nil {
		writeJSON(w, okResult(false, "Failed to load ONNX model: "+err.Error()))
		return
	}
	s.mlPredictor = predictor
	s.mlStatus = models.MLModelStatus{
		Loaded:              true,
		FilePath:            req.FilePath,
		ModelName:           filepath.Base(req.FilePath),
		ModelType:           "ONNX Runtime",
		LoadedAt:            time.Now().Format(time.RFC3339),
		Enabled:             false,
		FeatureCount:        14,
		ConfidenceThreshold: 0.75,
	}
	s.applyMLToRunningDetection()
	writeJSON(w, okResult(true, "Model loaded: "+s.mlStatus.ModelName))
}

func (s *Server) handleMLUnload(w http.ResponseWriter, r *http.Request) {
	s.mlMux.Lock()
	defer s.mlMux.Unlock()
	if s.mlPredictor != nil {
		s.mlPredictor.Close()
		s.mlPredictor = nil
	}
	s.mu.Lock()
	det := s.detection
	s.mu.Unlock()
	if det != nil {
		det.SetMLPredictor(nil)
		det.SetMLEnabled(false)
	}
	s.mlStatus = models.MLModelStatus{}
	writeJSON(w, okResult(true, "Model unloaded successfully"))
}

func (s *Server) handleMLEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mlMux.Lock()
	defer s.mlMux.Unlock()
	if !s.mlStatus.Loaded && req.Enabled {
		writeJSON(w, okResult(false, "Cannot enable ML detection: no model loaded"))
		return
	}
	s.mlStatus.Enabled = req.Enabled
	s.mu.Lock()
	det := s.detection
	s.mu.Unlock()
	if det != nil {
		det.SetMLEnabled(req.Enabled)
	}
	writeJSON(w, okResult(true, "ML detection updated"))
}

func (s *Server) handleMLConfidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Threshold float64 `json:"threshold"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Threshold < 0.0 || req.Threshold > 1.0 {
		writeJSON(w, okResult(false, "Threshold must be between 0.0 and 1.0"))
		return
	}
	s.mlMux.Lock()
	defer s.mlMux.Unlock()
	s.mlStatus.ConfidenceThreshold = req.Threshold
	s.mu.Lock()
	det := s.detection
	s.mu.Unlock()
	if det != nil {
		det.SetMLConfidence(req.Threshold)
	}
	writeJSON(w, okResult(true, "Confidence threshold updated"))
}

func (s *Server) handleDetectionMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Mode string `json:"mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !config.IsValidDetectionMode(req.Mode) {
			writeJSON(w, okResult(false, "Invalid detection mode. Must be rules_only, hybrid, or ml_only"))
			return
		}
		s.mlMux.RLock()
		mlLoaded := s.mlStatus.Loaded
		s.mlMux.RUnlock()
		if config.DetectionModeRequiresML(req.Mode) && !mlLoaded {
			writeJSON(w, okResult(false, "Cannot set "+req.Mode+" mode: no ML model loaded"))
			return
		}
		s.mu.Lock()
		det := s.detection
		s.mu.Unlock()
		if det != nil {
			det.SetDetectionMode(req.Mode)
		}
		if s.responseCfg != nil {
			s.responseCfg.ResponseSettings.DetectionMode = req.Mode
		}
		writeJSON(w, okResult(true, "Detection mode set to "+req.Mode))
		return
	}
	mode := "rules_only"
	s.mu.Lock()
	det := s.detection
	s.mu.Unlock()
	if det != nil {
		mode = det.GetDetectionMode()
	} else if s.responseCfg != nil && s.responseCfg.ResponseSettings.DetectionMode != "" {
		mode = s.responseCfg.ResponseSettings.DetectionMode
	}
	writeJSON(w, map[string]string{"mode": mode})
}

func (s *Server) handleCanaryAction(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Action != "terminate" && req.Action != "suspend" && req.Action != "alert_only" {
			writeJSON(w, okResult(false, "Invalid canary response action. Must be terminate, suspend, or alert_only"))
			return
		}
		s.mu.Lock()
		det := s.detection
		s.mu.Unlock()
		if det != nil {
			det.SetCanaryResponseAction(req.Action)
		}
		if s.responseCfg != nil {
			s.responseCfg.ResponseSettings.CanaryResponseAction = req.Action
		}
		writeJSON(w, okResult(true, "Canary response action set to "+req.Action))
		return
	}
	action := "terminate"
	s.mu.Lock()
	det := s.detection
	s.mu.Unlock()
	if det != nil {
		action = det.GetCanaryResponseAction()
	} else if s.responseCfg != nil && s.responseCfg.ResponseSettings.CanaryResponseAction != "" {
		action = s.responseCfg.ResponseSettings.CanaryResponseAction
	}
	writeJSON(w, map[string]string{"action": action})
}
