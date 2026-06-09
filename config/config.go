package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds application configuration
type Config struct {
	// Monitoring settings
	MonitorInterval    time.Duration
	MaxConcurrentOps   int
	EnableDetailedLogs bool

	// Detection settings
	EnableRansomNoteDetection bool     // Enable/disable ransom note detection (default: false, focus on behavioral detection)
	RansomwareExtensions      []string // Single source of truth: copied from ResponseConfig by the composition root, not by Load()

	// Performance settings
	WorkerPoolSize    int
	ChannelBufferSize int
}

// Load loads configuration from environment variables with defaults.
//
// RansomwareExtensions is intentionally NOT populated here. It is sourced from the
// embedded/on-disk ResponseConfig (see LoadResponseConfig) so there is a single source
// of truth for the extension list, rather than two loaders that can drift apart.
func Load() *Config {
	return &Config{
		MonitorInterval:           getDurationEnv("MONITOR_INTERVAL", 1*time.Second),
		MaxConcurrentOps:          getIntEnv("MAX_CONCURRENT_OPS", 10),
		EnableDetailedLogs:        getBoolEnv("DETAILED_LOGS", true),                 // Default: true (verbose BackupRead/BackupWrite API logging)
		EnableRansomNoteDetection: getBoolEnv("ENABLE_RANSOM_NOTE_DETECTION", false), // Default: false (focus on behavioral detection)
		WorkerPoolSize:            getIntEnv("WORKER_POOL_SIZE", 8),
		ChannelBufferSize:         getIntEnv("CHANNEL_BUFFER_SIZE", 100),
	}
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
