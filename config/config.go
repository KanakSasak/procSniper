package config

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// RansomwareConfig represents the structure of ransomware_extensions.json
type RansomwareConfig struct {
	RansomwareExtensions []string `json:"ransomware_extensions"`
}

// Config holds application configuration
type Config struct {
	// Monitoring settings
	MonitorInterval    time.Duration
	MaxConcurrentOps   int
	EnableDetailedLogs bool

	// Detection settings
	EnableRansomNoteDetection bool     // Enable/disable ransom note detection (default: false, focus on behavioral detection)
	RansomwareExtensions      []string // List of ransomware file extensions to detect

	// Performance settings
	WorkerPoolSize    int
	ChannelBufferSize int
}

// loadRansomwareExtensionsFromJSON loads ransomware extensions from JSON file
func loadRansomwareExtensionsFromJSON() []string {
	// Default extensions to use if file cannot be read
	defaultRansomwareExtensions := []string{
		".encrypted", ".locked", ".enc", ".crypt", ".locky", ".cerber",
		".zepto", ".thor", ".aesir", ".cryptolocker", ".cryptowall",
		".teslacrypt", ".wannacry", ".wcry", ".wncry", ".lockbit",
		".ryuk", ".sodinokibi", ".revil", ".conti", ".blackmatter",
		".alphv", ".hive",
	}

	// Get the path to the JSON config file
	configPath := filepath.Join("config", "ransomware_extensions.json")

	// Read the JSON file
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("[!] WARNING: Failed to read ransomware_extensions.json: %v", err)
		log.Printf("[!] Using default ransomware extensions")
		return defaultRansomwareExtensions
	}

	// Parse the JSON
	var ransomwareConfig RansomwareConfig
	if err := json.Unmarshal(data, &ransomwareConfig); err != nil {
		log.Printf("[!] WARNING: Failed to parse ransomware_extensions.json: %v", err)
		log.Printf("[!] Using default ransomware extensions")
		return defaultRansomwareExtensions
	}

	// Check if we got any extensions
	if len(ransomwareConfig.RansomwareExtensions) == 0 {
		log.Printf("[!] WARNING: No ransomware extensions found in config file")
		log.Printf("[!] Using default ransomware extensions")
		return defaultRansomwareExtensions
	}

	log.Printf("[+] Loaded %d ransomware extensions from config/ransomware_extensions.json", len(ransomwareConfig.RansomwareExtensions))
	return ransomwareConfig.RansomwareExtensions
}

// Load loads configuration from environment variables with defaults
func Load() *Config {
	return &Config{
		MonitorInterval:           getDurationEnv("MONITOR_INTERVAL", 1*time.Second),
		MaxConcurrentOps:          getIntEnv("MAX_CONCURRENT_OPS", 10),
		EnableDetailedLogs:        getBoolEnv("DETAILED_LOGS", true),                 // Default: true (verbose BackupRead/BackupWrite API logging)
		EnableRansomNoteDetection: getBoolEnv("ENABLE_RANSOM_NOTE_DETECTION", false), // Default: false (focus on behavioral detection)
		RansomwareExtensions:      loadRansomwareExtensionsFromJSON(),                // Load from config/ransomware_extensions.json
		WorkerPoolSize:            getIntEnv("WORKER_POOL_SIZE", 8),
		ChannelBufferSize:         getIntEnv("CHANNEL_BUFFER_SIZE", 100),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
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
