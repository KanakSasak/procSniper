//go:build windows

package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// LogCapture captures log output and stores recent entries
type LogCapture struct {
	entries    []LogEntry
	maxEntries int
	mu         sync.RWMutex
	listeners  []chan LogEntry
	listenerMu sync.RWMutex
}

// Global log capture instance
var globalCapture *LogCapture
var once sync.Once

// GetLogCapture returns the global log capture instance
func GetLogCapture() *LogCapture {
	once.Do(func() {
		globalCapture = NewLogCapture(500) // Keep last 500 log entries
		globalCapture.Install()
	})
	return globalCapture
}

// NewLogCapture creates a new log capture
func NewLogCapture(maxEntries int) *LogCapture {
	return &LogCapture{
		entries:    make([]LogEntry, 0, maxEntries),
		maxEntries: maxEntries,
		listeners:  make([]chan LogEntry, 0),
	}
}

// logWriter implements io.Writer to capture log output
type logWriter struct {
	capture  *LogCapture
	original io.Writer
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	// Write to original output
	n, err = w.original.Write(p)

	// Parse and store log entry
	message := string(p)
	if len(message) > 0 {
		entry := LogEntry{
			Timestamp: time.Now().Format("15:04:05.000"),
			Level:     detectLogLevel(message),
			Message:   message,
		}

		w.capture.addEntry(entry)
	}

	return n, err
}

// detectLogLevel tries to detect the log level from the message
func detectLogLevel(message string) string {
	if len(message) < 3 {
		return "INFO"
	}

	// Check for common patterns
	if contains(message, "[!]") || contains(message, "ERROR") || contains(message, "FAILED") {
		return "ERROR"
	}
	if contains(message, "[+]") || contains(message, "SUCCESS") {
		return "SUCCESS"
	}
	if contains(message, "[*]") || contains(message, "INFO") {
		return "INFO"
	}
	if contains(message, "WARNING") || contains(message, "WARN") {
		return "WARN"
	}
	if contains(message, "[DETECTION]") || contains(message, "THREAT") || contains(message, "ALERT") {
		return "ALERT"
	}
	if contains(message, "[FILE_CREATED]") || contains(message, "[FILE_MODIFIED]") {
		return "DEBUG"
	}

	return "INFO"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Install installs the log capture as the default log output
func (lc *LogCapture) Install() {
	writer := &logWriter{
		capture:  lc,
		original: os.Stderr,
	}
	log.SetOutput(writer)
}

// addEntry adds a new log entry
func (lc *LogCapture) addEntry(entry LogEntry) {
	lc.mu.Lock()

	// Add entry
	lc.entries = append(lc.entries, entry)

	// Trim if over capacity
	if len(lc.entries) > lc.maxEntries {
		lc.entries = lc.entries[len(lc.entries)-lc.maxEntries:]
	}

	lc.mu.Unlock()

	// Notify listeners
	lc.listenerMu.RLock()
	for _, ch := range lc.listeners {
		select {
		case ch <- entry:
		default:
			// Channel full, skip
		}
	}
	lc.listenerMu.RUnlock()
}

// GetEntries returns the recent log entries
func (lc *LogCapture) GetEntries(limit int) []LogEntry {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	if limit <= 0 || limit > len(lc.entries) {
		limit = len(lc.entries)
	}

	start := len(lc.entries) - limit
	if start < 0 {
		start = 0
	}

	result := make([]LogEntry, limit)
	copy(result, lc.entries[start:])
	return result
}

// Subscribe returns a channel that receives new log entries
func (lc *LogCapture) Subscribe() chan LogEntry {
	ch := make(chan LogEntry, 100)
	lc.listenerMu.Lock()
	lc.listeners = append(lc.listeners, ch)
	lc.listenerMu.Unlock()
	return ch
}

// Unsubscribe removes a subscription channel
func (lc *LogCapture) Unsubscribe(ch chan LogEntry) {
	lc.listenerMu.Lock()
	defer lc.listenerMu.Unlock()

	for i, listener := range lc.listeners {
		if listener == ch {
			lc.listeners = append(lc.listeners[:i], lc.listeners[i+1:]...)
			close(ch)
			return
		}
	}
}

// Clear clears all log entries
func (lc *LogCapture) Clear() {
	lc.mu.Lock()
	lc.entries = lc.entries[:0]
	lc.mu.Unlock()
}

// AddManualEntry adds a manual log entry (for GUI-specific messages)
func (lc *LogCapture) AddManualEntry(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05.000"),
		Level:     level,
		Message:   fmt.Sprintf("[GUI] %s\n", message),
	}
	lc.addEntry(entry)
}
