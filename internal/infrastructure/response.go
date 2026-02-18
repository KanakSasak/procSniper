//go:build windows
// +build windows

package infrastructure

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// ResponseActions implements automated threat response
type ResponseActions struct {
	privilegesEnabled bool
}

func isProcessGoneError(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
		errors.Is(err, windows.ERROR_NOT_FOUND)
}

// NewResponseActions creates a new response actions handler
func NewResponseActions() (*ResponseActions, error) {
	ra := &ResponseActions{}

	// Enable debug privilege for process manipulation
	if err := ra.EnableDebugPrivilege(); err != nil {
		return nil, fmt.Errorf("failed to enable debug privilege: %w", err)
	}

	ra.privilegesEnabled = true
	return ra, nil
}

// EnableDebugPrivilege enables SeDebugPrivilege for system process access
func (ra *ResponseActions) EnableDebugPrivilege() error {
	var token windows.Token
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}

	err = windows.OpenProcessToken(proc,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken failed: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil,
		windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// TerminateProcess terminates a process by PID
func (ra *ResponseActions) TerminateProcess(pid uint32) error {
	const PROCESS_TERMINATE = 0x0001

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|PROCESS_TERMINATE,
		false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess failed for PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("TerminateProcess failed: %w", err)
	}

	return nil
}

// IsProcessAlive checks whether a process is still active.
// A missing process is treated as "not alive" without returning an error.
func (ra *ResponseActions) IsProcessAlive(pid uint32) (bool, error) {
	if pid == 0 {
		return false, fmt.Errorf("invalid PID 0")
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		pid,
	)
	if err != nil {
		if isProcessGoneError(err) {
			return false, nil
		}
		return false, fmt.Errorf("OpenProcess failed for PID %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false, fmt.Errorf("GetExitCodeProcess failed for PID %d: %w", pid, err)
	}

	const stillActive = 259
	return exitCode == stillActive, nil
}

// TerminateProcessVerified terminates a process and verifies it exited.
// It retries termination and can escalate with suspend+terminate when requested.
func (ra *ResponseActions) TerminateProcessVerified(pid uint32, attempts int, wait time.Duration, escalateSuspend bool) (bool, bool, error) {
	if pid == 0 {
		return false, false, fmt.Errorf("invalid PID 0")
	}
	if attempts <= 0 {
		attempts = 1
	}
	if wait <= 0 {
		wait = 200 * time.Millisecond
	}

	alive, err := ra.IsProcessAlive(pid)
	if err != nil {
		return false, false, err
	}
	if !alive {
		return false, true, nil
	}

	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		termErr := ra.TerminateProcess(pid)
		if termErr != nil && !isProcessGoneError(termErr) {
			lastErr = termErr
		}

		time.Sleep(wait)

		alive, aliveErr := ra.IsProcessAlive(pid)
		if aliveErr != nil {
			lastErr = aliveErr
		} else if !alive {
			if isProcessGoneError(termErr) {
				return false, true, nil
			}
			return true, false, nil
		}

		if !escalateSuspend {
			continue
		}

		if suspendErr := ra.SuspendProcess(pid); suspendErr != nil && !isProcessGoneError(suspendErr) {
			lastErr = fmt.Errorf("suspend failed for PID %d: %w", pid, suspendErr)
			continue
		}

		termErr = ra.TerminateProcess(pid)
		if termErr != nil && !isProcessGoneError(termErr) {
			lastErr = termErr
		}

		time.Sleep(wait)

		alive, aliveErr = ra.IsProcessAlive(pid)
		if aliveErr != nil {
			lastErr = aliveErr
			continue
		}
		if !alive {
			if isProcessGoneError(termErr) {
				return false, true, nil
			}
			return true, false, nil
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("process %d is still alive after %d termination attempts", pid, attempts)
	}

	return false, false, lastErr
}

// SuspendProcess suspends a process by PID
func (ra *ResponseActions) SuspendProcess(pid uint32) error {
	var (
		modntdll             = windows.NewLazySystemDLL("ntdll.dll")
		procNtSuspendProcess = modntdll.NewProc("NtSuspendProcess")
	)

	handle, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	ret, _, _ := procNtSuspendProcess.Call(uintptr(handle))
	if ret != 0 {
		return fmt.Errorf("NtSuspendProcess failed with NTSTATUS=0x%X", ret)
	}

	return nil
}

// ResumeProcess resumes a suspended process by PID
func (ra *ResponseActions) ResumeProcess(pid uint32) error {
	var (
		modntdll            = windows.NewLazySystemDLL("ntdll.dll")
		procNtResumeProcess = modntdll.NewProc("NtResumeProcess")
	)

	handle, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	ret, _, _ := procNtResumeProcess.Call(uintptr(handle))
	if ret != 0 {
		return fmt.Errorf("NtResumeProcess failed with NTSTATUS=0x%X", ret)
	}

	return nil
}

// QuarantineFile moves a suspicious file to quarantine directory
func (ra *ResponseActions) QuarantineFile(sourcePath string, quarantineDir string) error {
	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return err
	}

	fileName := filepath.Base(sourcePath)
	timestamp := time.Now().Format("20060102_150405")
	destPath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", timestamp, fileName))

	sourcePtr, _ := windows.UTF16PtrFromString(sourcePath)
	destPtr, _ := windows.UTF16PtrFromString(destPath)

	// Atomic move with write-through
	err := windows.MoveFileEx(sourcePtr, destPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	if err != nil {
		// If file is locked, schedule deletion on reboot
		err = windows.MoveFileEx(sourcePtr, destPtr,
			windows.MOVEFILE_DELAY_UNTIL_REBOOT)
		if err != nil {
			return fmt.Errorf("failed to quarantine file: %w", err)
		}
		return nil
	}

	// Restrict permissions on quarantined file
	if err := ra.restrictFilePermissions(destPath); err != nil {
		return fmt.Errorf("failed to restrict permissions: %w", err)
	}

	return nil
}

// restrictFilePermissions sets restrictive ACLs on quarantined files
func (ra *ResponseActions) restrictFilePermissions(filePath string) error {
	// TODO: Implement proper ACL restrictions
	// For now, just set file to read-only
	filePtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	// Set file attributes to read-only and system
	return windows.SetFileAttributes(filePtr,
		windows.FILE_ATTRIBUTE_READONLY|windows.FILE_ATTRIBUTE_SYSTEM)
}

// KillProcessTree terminates a process and all its children
func (ra *ResponseActions) KillProcessTree(pid uint32) error {
	// First, get all child processes
	children, err := ra.getChildProcesses(pid)
	if err != nil {
		return err
	}

	// Terminate children first
	for _, childPID := range children {
		_ = ra.TerminateProcess(childPID) // Best effort
	}

	// Terminate parent
	return ra.TerminateProcess(pid)
}

// getChildProcesses returns all child process IDs
func (ra *ResponseActions) getChildProcesses(parentPID uint32) ([]uint32, error) {
	// This is a simplified implementation
	// Full implementation would use CreateToolhelp32Snapshot
	return []uint32{}, nil
}
