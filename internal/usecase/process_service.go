package usecase

import (
	"context"
	"fmt"

	"procSniper/internal/domain"
	"procSniper/internal/repository"
)

// ProcessService defines the interface for process management business logic
type ProcessService interface {
	ListProcesses(ctx context.Context) ([]*domain.Process, error)
	GetProcess(ctx context.Context, pid int) (*domain.Process, error)
	FindProcessByName(ctx context.Context, name string) ([]*domain.Process, error)
	TerminateProcess(ctx context.Context, pid int) error
	MonitorProcess(ctx context.Context, pid int) (<-chan *repository.ProcessStats, error)
}

// processService implements ProcessService
// Dependency Inversion Principle - depends on interfaces, not concrete implementations
type processService struct {
	processRepo       repository.ProcessRepository
	processController repository.ProcessController
	processMonitor    repository.ProcessMonitor
}

// NewProcessService creates a new process service
// Constructor injection - dependencies passed as interfaces
func NewProcessService(
	repo repository.ProcessRepository,
	controller repository.ProcessController,
	monitor repository.ProcessMonitor,
) ProcessService {
	return &processService{
		processRepo:       repo,
		processController: controller,
		processMonitor:    monitor,
	}
}

func (s *processService) ListProcesses(ctx context.Context) ([]*domain.Process, error) {
	processes, err := s.processRepo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	return processes, nil
}

func (s *processService) GetProcess(ctx context.Context, pid int) (*domain.Process, error) {
	if pid <= 0 {
		return nil, domain.ErrInvalidPID
	}

	process, err := s.processRepo.FindByPID(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to get process %d: %w", pid, err)
	}

	// Update with current stats
	stats, err := s.processMonitor.GetStats(ctx, pid)
	if err == nil {
		process.UpdateStats(stats.CPUPercent, stats.MemoryMB)
	}

	return process, nil
}

func (s *processService) FindProcessByName(ctx context.Context, name string) ([]*domain.Process, error) {
	if name == "" {
		return nil, domain.ErrInvalidProcessName
	}

	processes, err := s.processRepo.FindByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to find process by name %s: %w", name, err)
	}

	return processes, nil
}

func (s *processService) TerminateProcess(ctx context.Context, pid int) error {
	// Verify process exists
	process, err := s.processRepo.FindByPID(ctx, pid)
	if err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}

	// Check if already terminated
	if !process.IsRunning() {
		return domain.ErrProcessTerminated
	}

	// Terminate via controller
	if err := s.processController.Terminate(ctx, pid); err != nil {
		return fmt.Errorf("failed to terminate process %d: %w", pid, err)
	}

	// Update domain model
	if err := process.Terminate(); err != nil {
		return err
	}

	return nil
}

func (s *processService) MonitorProcess(ctx context.Context, pid int) (<-chan *repository.ProcessStats, error) {
	// Verify process exists
	_, err := s.processRepo.FindByPID(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("process %d not found: %w", pid, err)
	}

	// Start monitoring
	statsChan, err := s.processMonitor.WatchProcess(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("failed to start monitoring process %d: %w", pid, err)
	}

	return statsChan, nil
}
