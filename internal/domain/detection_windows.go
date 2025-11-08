//go:build windows

package domain

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// OpenFileShared opens a file using Windows API with FILE_SHARE_READ|FILE_SHARE_WRITE
// This allows reading files even when ransomware has them locked with exclusive write access
func OpenFileShared(filePath string) (*os.File, error) {
	// Convert path to UTF16 for Windows API
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to convert path: %w", err)
	}

	// Windows CreateFile parameters
	// GENERIC_READ: We want to read the file
	// FILE_SHARE_READ|FILE_SHARE_WRITE: Allow other processes to read/write while we read
	// OPEN_EXISTING: Only open if file exists
	// FILE_ATTRIBUTE_NORMAL: Standard file attributes
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ, // dwDesiredAccess
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // dwShareMode (KEY: allows reading locked files)
		nil,                           // lpSecurityAttributes
		windows.OPEN_EXISTING,         // dwCreationDisposition
		windows.FILE_ATTRIBUTE_NORMAL, // dwFlagsAndAttributes
		0,                             // hTemplateFile
	)

	if err != nil {
		return nil, fmt.Errorf("CreateFile failed: %w", err)
	}

	// Convert Windows HANDLE to Go os.File
	file := os.NewFile(uintptr(handle), filePath)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to create os.File from handle")
	}

	return file, nil
}

// ReadFileWithRetry reads a file's content with retry logic and Windows API sharing modes
// This is the enhanced version that can read files locked by ransomware
func ReadFileWithRetry(filePath string, maxBytes int, maxRetries int) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Try Windows API with share modes first
		file, err := OpenFileShared(filePath)
		if err != nil {
			if isFileLocked(err) {
				lastErr = err
				// Exponential backoff: 50ms, 100ms, 150ms
				sleepDuration := time.Duration(50*(attempt+1)) * time.Millisecond
				time.Sleep(sleepDuration)
				continue
			}
			// Non-lock error, fail immediately
			return nil, err
		}
		defer file.Close()

		// Read up to maxBytes
		buffer := make([]byte, maxBytes)
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			file.Close()
			if isFileLocked(err) {
				lastErr = err
				continue
			}
			return nil, err
		}

		return buffer[:n], nil
	}

	return nil, fmt.Errorf("file still locked after %d retries: %w", maxRetries, lastErr)
}

// openFileForEntropy opens a file for entropy analysis using Windows API
// Returns a file handle that can read even if the file is locked by ransomware
func openFileForEntropy(filePath string) (*os.File, error) {
	// First attempt: Use Windows API with share modes (can read locked files)
	file, err := OpenFileShared(filePath)
	if err == nil {
		return file, nil
	}

	// Second attempt: Fallback to standard os.Open (for non-Windows or simple cases)
	// This will fail if file is exclusively locked, but works for normal files
	file, err2 := os.Open(filePath)
	if err2 == nil {
		return file, nil
	}

	// Both methods failed, return original Windows API error
	return nil, fmt.Errorf("cannot open file (Windows API: %v, os.Open: %v)", err, err2)
}
