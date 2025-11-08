package domain

import (
	"errors"
	"time"
)

var (
	ErrProcessNotFound    = errors.New("process not found")
	ErrInvalidPID         = errors.New("invalid process ID")
	ErrInvalidProcessName = errors.New("invalid process name")
	ErrProcessTerminated  = errors.New("process already terminated")
)

// Process represents a system process entity
type Process struct {
	PID       int
	Name      string
	Path      string
	Status    ProcessStatus
	StartTime time.Time
	CPUUsage  float64
	MemoryMB  uint64
}

// ProcessStatus represents the current state of a process
type ProcessStatus string

const (
	StatusRunning    ProcessStatus = "running"
	StatusStopped    ProcessStatus = "stopped"
	StatusSuspended  ProcessStatus = "suspended"
	StatusTerminated ProcessStatus = "terminated"
)

// NewProcess creates a new process entity with validation
func NewProcess(pid int, name, path string) (*Process, error) {
	if pid <= 0 {
		return nil, ErrInvalidPID
	}

	if name == "" {
		return nil, ErrInvalidProcessName
	}

	return &Process{
		PID:       pid,
		Name:      name,
		Path:      path,
		Status:    StatusRunning,
		StartTime: time.Now(),
	}, nil
}

// Validate validates process data
func (p *Process) Validate() error {
	if p.PID <= 0 {
		return ErrInvalidPID
	}

	if p.Name == "" {
		return ErrInvalidProcessName
	}

	return nil
}

// IsRunning checks if the process is currently running
func (p *Process) IsRunning() bool {
	return p.Status == StatusRunning
}

// Terminate marks the process as terminated
func (p *Process) Terminate() error {
	if p.Status == StatusTerminated {
		return ErrProcessTerminated
	}

	p.Status = StatusTerminated
	return nil
}

// UpdateStats updates process statistics
func (p *Process) UpdateStats(cpuUsage float64, memoryMB uint64) {
	p.CPUUsage = cpuUsage
	p.MemoryMB = memoryMB
}
