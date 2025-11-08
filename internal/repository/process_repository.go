package repository

import (
	"context"

	"procSniper/internal/domain"
)

// ProcessRepository defines the interface for process data access
// Following Interface Segregation Principle - small, focused interface
type ProcessRepository interface {
	FindAll(ctx context.Context) ([]*domain.Process, error)
	FindByPID(ctx context.Context, pid int) (*domain.Process, error)
	FindByName(ctx context.Context, name string) ([]*domain.Process, error)
}

// ProcessController defines the interface for process control operations
// Separated from query operations (Interface Segregation Principle)
type ProcessController interface {
	Terminate(ctx context.Context, pid int) error
	Suspend(ctx context.Context, pid int) error
	Resume(ctx context.Context, pid int) error
}

// ProcessMonitor defines the interface for process monitoring
type ProcessMonitor interface {
	GetStats(ctx context.Context, pid int) (*ProcessStats, error)
	WatchProcess(ctx context.Context, pid int) (<-chan *ProcessStats, error)
}

// ProcessStats represents process statistics
type ProcessStats struct {
	PID         int
	CPUPercent  float64
	MemoryMB    uint64
	ThreadCount int
	HandleCount int
}
