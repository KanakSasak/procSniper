package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"procSniper/internal/usecase"
)

// ProcessCLI handles command-line interface for process operations
type ProcessCLI struct {
	processService usecase.ProcessService
}

// NewProcessCLI creates a new CLI handler
func NewProcessCLI(service usecase.ProcessService) *ProcessCLI {
	return &ProcessCLI{
		processService: service,
	}
}

// ListProcesses displays all running processes
func (c *ProcessCLI) ListProcesses(ctx context.Context) error {
	processes, err := c.processService.ListProcesses(ctx)
	if err != nil {
		return fmt.Errorf("failed to list processes: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tNAME\tCPU%\tMEMORY(MB)\tSTATUS")
	fmt.Fprintln(w, "---\t----\t----\t----------\t------")

	for _, p := range processes {
		fmt.Fprintf(w, "%d\t%s\t%.2f\t%d\t%s\n",
			p.PID, p.Name, p.CPUUsage, p.MemoryMB, p.Status)
	}

	return w.Flush()
}

// ShowProcess displays detailed information about a specific process
func (c *ProcessCLI) ShowProcess(ctx context.Context, pid int) error {
	process, err := c.processService.GetProcess(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to get process: %w", err)
	}

	fmt.Printf("Process Information:\n")
	fmt.Printf("  PID:          %d\n", process.PID)
	fmt.Printf("  Name:         %s\n", process.Name)
	fmt.Printf("  Path:         %s\n", process.Path)
	fmt.Printf("  Status:       %s\n", process.Status)
	fmt.Printf("  Start Time:   %s\n", process.StartTime.Format(time.RFC3339))
	fmt.Printf("  CPU Usage:    %.2f%%\n", process.CPUUsage)
	fmt.Printf("  Memory:       %d MB\n", process.MemoryMB)

	return nil
}

// KillProcess terminates a process by PID
func (c *ProcessCLI) KillProcess(ctx context.Context, pid int) error {
	fmt.Printf("Terminating process %d...\n", pid)

	if err := c.processService.TerminateProcess(ctx, pid); err != nil {
		return fmt.Errorf("failed to terminate process: %w", err)
	}

	fmt.Printf("Process %d terminated successfully\n", pid)
	return nil
}

// MonitorProcess continuously monitors a process
func (c *ProcessCLI) MonitorProcess(ctx context.Context, pid int) error {
	fmt.Printf("Monitoring process %d (Press Ctrl+C to stop)...\n\n", pid)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nStopping monitor...")
		cancel()
	}()

	// Start monitoring
	statsChan, err := c.processService.MonitorProcess(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to start monitoring: %w", err)
	}

	// Display stats
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tCPU%\tMEMORY(MB)\tTHREADS\tHANDLES")

	for stats := range statsChan {
		fmt.Fprintf(w, "%s\t%.2f\t%d\t%d\t%d\n",
			time.Now().Format("15:04:05"),
			stats.CPUPercent,
			stats.MemoryMB,
			stats.ThreadCount,
			stats.HandleCount,
		)
		w.Flush()
	}

	return nil
}

// FindProcessByName finds and displays processes by name
func (c *ProcessCLI) FindProcessByName(ctx context.Context, name string) error {
	processes, err := c.processService.FindProcessByName(ctx, name)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	if len(processes) == 0 {
		fmt.Printf("No processes found with name: %s\n", name)
		return nil
	}

	fmt.Printf("Found %d process(es) with name '%s':\n\n", len(processes), name)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PID\tNAME\tPATH\tSTATUS")
	fmt.Fprintln(w, "---\t----\t----\t------")

	for _, p := range processes {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			p.PID, p.Name, p.Path, p.Status)
	}

	return w.Flush()
}
