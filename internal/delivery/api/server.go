//go:build windows

// Package api is the local HTTP+SSE delivery surface over the detection engine. The detection agent
// (internal/app.Agent) runs headless (as a Windows service); this server exposes control + reads as
// JSON, live data as Server-Sent Events, and serves the React console as static files — so any
// browser is the UI, with no WebView2/Wails dependency. It owns the role the Wails App used to play:
// agent lifecycle, the operator-owned ML model state, and the event fan-out (now SSE instead of Wails).
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"procSniper/config"
	"procSniper/internal/app"
	"procSniper/internal/delivery/gui/logger"
	"procSniper/internal/delivery/gui/models"
	"procSniper/internal/domain"
	"procSniper/internal/infrastructure"
	"procSniper/internal/usecase"
)

// Server is the local API over the detection engine.
type Server struct {
	addr     string
	token    string
	staticFS fs.FS

	cfg         *config.Config
	responseCfg *config.ResponseConfig
	configPath  string // where SaveConfig writes (absolute under the service install root)

	logCapture *logger.LogCapture
	hub        *sseHub

	// protection lifecycle (guarded by mu)
	mu           sync.Mutex
	agent        *app.Agent
	detection    *usecase.DetectionService
	orchestrator *usecase.ResponseOrchestrator
	etw          *infrastructure.KernelETWConsumer
	isProtecting bool
	stopStreams  chan struct{} // stops the per-run SSE feed goroutines

	// ML model state, owned across protection runs (guarded by mlMux)
	mlMux       sync.RWMutex
	mlPredictor domain.MLPredictor
	mlStatus    models.MLModelStatus

	http *http.Server
}

// NewServer builds the API server. staticFS is the embedded frontend build (cmd/gui/dist) or nil.
func NewServer(addr string, cfg *config.Config, responseCfg *config.ResponseConfig, staticFS fs.FS) (*Server, error) {
	token, err := generateToken()
	if err != nil {
		return nil, err
	}
	s := &Server{
		addr:        addr,
		token:       token,
		staticFS:    staticFS,
		cfg:         cfg,
		responseCfg: responseCfg,
		configPath:  defaultConfigPath,
		logCapture:  logger.GetLogCapture(),
		hub:         newSSEHub(),
	}
	s.http = &http.Server{Addr: addr, Handler: s.routes()}
	return s, nil
}

// SetConfigPath overrides where SaveConfig persists (e.g. an absolute path under the install root
// for the LocalSystem service, whose cwd is System32).
func (s *Server) SetConfigPath(path string) { s.configPath = path }

// Token returns the bearer token required by the API.
func (s *Server) Token() string { return s.token }

// WriteTokenFile persists the token so the tray/operator can read it (file ACLs are the installer's job).
func (s *Server) WriteTokenFile(path string) error {
	return os.WriteFile(path, []byte(s.token), 0o600)
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ListenAndServe binds loopback and serves until Shutdown (blocking).
func (s *Server) ListenAndServe() error {
	log.Printf("[API] listening on http://%s", s.addr)
	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops protection (idempotent) then the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.StopProtection()
	return s.http.Shutdown(ctx)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// SSE stream — token via query param (EventSource cannot set headers).
	mux.HandleFunc("/api/stream", s.requireTokenQuery(s.hub.serveStream))

	// reads
	mux.HandleFunc("/api/protect/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/stats", s.auth(s.handleStats))
	mux.HandleFunc("/api/threats", s.auth(s.handleThreats))
	mux.HandleFunc("/api/config", s.auth(s.handleConfig)) // GET + POST
	mux.HandleFunc("/api/ml/status", s.auth(s.handleMLStatus))
	mux.HandleFunc("/api/logs", s.auth(s.handleLogs)) // GET (?limit) + DELETE (clear)

	// control
	mux.HandleFunc("/api/protect/start", s.auth(s.handleStart))
	mux.HandleFunc("/api/protect/stop", s.auth(s.handleStop))
	mux.HandleFunc("/api/ml/load", s.auth(s.handleMLLoad))
	mux.HandleFunc("/api/ml/unload", s.auth(s.handleMLUnload))
	mux.HandleFunc("/api/ml/enable", s.auth(s.handleMLEnable))
	mux.HandleFunc("/api/ml/confidence", s.auth(s.handleMLConfidence))
	mux.HandleFunc("/api/detection-mode", s.auth(s.handleDetectionMode))
	mux.HandleFunc("/api/canary-action", s.auth(s.handleCanaryAction))

	// static frontend (assets unauthenticated; the /api/* surface is token-gated)
	if s.staticFS != nil {
		mux.Handle("/", s.staticHandler())
	}
	return mux
}

// auth gates an endpoint on the bearer token (Authorization: Bearer <token>).
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !tokenEqual(got, s.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// requireTokenQuery gates the SSE stream on a ?token= query param.
func (s *Server) requireTokenQuery(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenEqual(r.URL.Query().Get("token"), s.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// staticHandler serves the embedded SPA, falling back to index.html for client-side routes.
func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.staticFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.staticFS, p); err != nil {
			// Not a real asset → SPA route: serve index.html.
			indexBytes, e := fs.ReadFile(s.staticFS, "index.html")
			if e != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexBytes)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
