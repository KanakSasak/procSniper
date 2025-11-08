//go:build windows

package infrastructure

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// SetupLogging configures logging to both console and file
// Returns the log file handle (caller should close it with defer)
func SetupLogging(logDir string) (*os.File, error) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Generate log filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	logFilename := filepath.Join(logDir, fmt.Sprintf("procsniper_%s.log", timestamp))

	// Open log file (create if doesn't exist, append if exists)
	logFile, err := os.OpenFile(logFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Create multi-writer: write to both stdout and file
	multiWriter := io.MultiWriter(os.Stdout, logFile)

	// Set log output to multi-writer
	log.SetOutput(multiWriter)

	// Set log format (date, time, microseconds, file:line)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	log.Printf("[+] Logging initialized: %s\n", logFilename)
	log.Printf("[+] Logs will be written to both console and file\n")

	return logFile, nil
}

// SetupLoggingFileOnly configures logging to file only (no console output)
func SetupLoggingFileOnly(logDir string) (*os.File, error) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Generate log filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	logFilename := filepath.Join(logDir, fmt.Sprintf("procsniper_%s.log", timestamp))

	// Open log file
	logFile, err := os.OpenFile(logFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Set log output to file only
	log.SetOutput(logFile)

	// Set log format
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	fmt.Printf("[+] Logging initialized: %s\n", logFilename)
	fmt.Printf("[+] Logs will be written to file only (check %s)\n", logFilename)

	return logFile, nil
}

// CleanupOldLogs removes log files older than specified duration
func CleanupOldLogs(logDir string, maxAge time.Duration) error {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return fmt.Errorf("failed to read log directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .log files
		if filepath.Ext(entry.Name()) != ".log" {
			continue
		}

		fullPath := filepath.Join(logDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Remove if older than cutoff
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(fullPath); err != nil {
				log.Printf("[!] Failed to remove old log file %s: %v\n", fullPath, err)
			} else {
				removed++
				log.Printf("[CLEANUP] Removed old log file: %s\n", entry.Name())
			}
		}
	}

	if removed > 0 {
		log.Printf("[CLEANUP] Removed %d old log files (older than %v)\n", removed, maxAge)
	}

	return nil
}
