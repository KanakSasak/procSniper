//go:build windows && !gui

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"procSniper/config"
	"procSniper/internal/delivery/api"
)

const (
	serviceName    = "procSniper"
	serviceDisplay = "procSniper Ransomware Detection"
	serviceDesc    = "Real-time ransomware & stealer detection agent (kernel ETW). Hosts a local HTTP/SSE console on 127.0.0.1."
)

// runService dispatches `procSniper service <install|remove|start|stop|run> [--addr ...]`.
// `run` is invoked by the Windows SCM; install/remove/start/stop manage the service (need admin).
func runService(cfg *config.Config, responseCfg *config.ResponseConfig) {
	if len(os.Args) < 3 {
		fmt.Println("Usage: procSniper service <install|remove|start|stop|run> [--addr 127.0.0.1:8787]")
		os.Exit(1)
	}
	action := os.Args[2]

	fs := flag.NewFlagSet("service", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8787", "API listen address (loopback only)")
	_ = fs.Parse(os.Args[3:])

	switch action {
	case "run":
		svcRun(cfg, responseCfg, *addr)
	case "install":
		if err := svcInstall(*addr); err != nil {
			log.Fatalf("[SVC] install failed: %v", err)
		}
		fmt.Printf("Service %q installed (Automatic start, addr %s). Start it with: procSniper service start\n", serviceName, *addr)
	case "remove":
		if err := svcRemove(); err != nil {
			log.Fatalf("[SVC] remove failed: %v", err)
		}
		fmt.Printf("Service %q removed.\n", serviceName)
	case "start":
		if err := svcControl(svc.Cmd(0)); err != nil {
			log.Fatalf("[SVC] start failed: %v", err)
		}
		fmt.Printf("Service %q started.\n", serviceName)
	case "stop":
		if err := svcControl(svc.Stop); err != nil {
			log.Fatalf("[SVC] stop failed: %v", err)
		}
		fmt.Printf("Service %q stopped.\n", serviceName)
	default:
		fmt.Printf("unknown service action %q (want install|remove|start|stop|run)\n", action)
		os.Exit(1)
	}
}

// svcRun builds the API server and hands control to the SCM via svc.Run.
func svcRun(cfg *config.Config, responseCfg *config.ResponseConfig, addr string) {
	staticFS, err := frontendFS()
	if err != nil {
		log.Printf("[SVC] frontend assets unavailable: %v", err)
		staticFS = nil
	}
	srv, err := api.NewServer(addr, cfg, responseCfg, staticFS)
	if err != nil {
		log.Fatalf("[SVC] failed to initialize server: %v", err)
	}
	// Persist the bearer token next to the exe so the tray/operator can read it.
	if exe, e := os.Executable(); e == nil {
		if err := srv.WriteTokenFile(filepath.Join(filepath.Dir(exe), "api_token")); err != nil {
			log.Printf("[SVC] could not write token file: %v", err)
		}
	}
	if err := svc.Run(serviceName, &serviceHandler{srv: srv}); err != nil {
		log.Fatalf("[SVC] service run failed: %v", err)
	}
}

// serviceHandler adapts the API server to the Windows service control lifecycle.
type serviceHandler struct {
	srv *api.Server
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Bring the API up and auto-start protection; both run in the background so the SCM sees us
	// Running promptly (ETW init must not delay the service-start handshake).
	go func() {
		if err := h.srv.ListenAndServe(); err != nil {
			log.Printf("[SVC] API server stopped: %v", err)
		}
	}()
	go func() {
		if res := h.srv.StartProtection(); !res.Success {
			log.Printf("[SVC] auto-start protection: %s", res.Message)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = h.srv.Shutdown(ctx) // stops protection (WaitGroup join) + the HTTP server
			cancel()
			return false, 0
		default:
			log.Printf("[SVC] unexpected control request #%d", c.Cmd)
		}
	}
	return false, 0
}

func svcInstall(addr string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: serviceDisplay,
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic,
	}, "service", "run", "--addr", addr)
	if err != nil {
		return err
	}
	defer s.Close()
	return nil
}

func svcRemove() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q not installed", serviceName)
	}
	defer s.Close()
	return s.Delete()
}

// svcControl starts the service (cmd == 0) or sends a control code (e.g. svc.Stop).
func svcControl(cmd svc.Cmd) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q not installed", serviceName)
	}
	defer s.Close()

	if cmd == 0 {
		return s.Start()
	}
	_, err = s.Control(cmd)
	return err
}
