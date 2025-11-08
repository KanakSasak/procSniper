package domain

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CanaryFile represents a honeypot file used to detect ransomware
// Canary files are decoy files with known low entropy placed in common directories
// If ransomware encrypts or deletes a canary file, we detect it immediately
type CanaryFile struct {
	Path            string
	OriginalEntropy float64
	FileSize        int64
	Created         time.Time
	LastChecked     time.Time
	Extension       string
}

// CanaryFileConfig defines common target directories and file types
var CanaryLocations = []struct {
	Directory string
	FileName  string
	Extension string
}{
	// Documents - high-value ransomware targets
	{Directory: "Documents", FileName: "~canary_tax_returns_2024.xlsx", Extension: ".xlsx"},
	{Directory: "Documents", FileName: "~canary_financial_summary.docx", Extension: ".docx"},
	{Directory: "Documents", FileName: "~canary_passwords_backup.txt", Extension: ".txt"},

	// Desktop - frequently encrypted location
	{Directory: "Desktop", FileName: "~canary_important_notes.txt", Extension: ".txt"},

	// Pictures - media files are common targets
	{Directory: "Pictures", FileName: "~canary_family_vacation.jpg", Extension: ".jpg"},

	// Downloads - often contains valuable files
	{Directory: "Downloads", FileName: "~canary_invoice_2024.pdf", Extension: ".pdf"},

	// Public folders - accessible to all processes
	{Directory: "Public\\Documents", FileName: "~canary_shared_project.xlsx", Extension: ".xlsx"},
}

// CanarySystemLocations defines canaries for system directories (Program Files)
// These require admin privileges to create, so they're separated from user locations
var CanarySystemLocations = []struct {
	Directory string
	FileName  string
	Extension string
}{
	// Program Files - system directory often targeted by ransomware
	{Directory: "C:\\Program Files\\ProcSniperCanary", FileName: "~canary_license_key.txt", Extension: ".txt"},
	{Directory: "C:\\Program Files\\ProcSniperCanary", FileName: "~canary_config_backup.xml", Extension: ".xml"},
	{Directory: "C:\\Program Files\\ProcSniperCanary", FileName: "~canary_database.dat", Extension: ".dat"},

	// Program Files (x86) - 32-bit programs directory
	{Directory: "C:\\Program Files (x86)\\ProcSniperCanary", FileName: "~canary_activation_data.bin", Extension: ".bin"},
	{Directory: "C:\\Program Files (x86)\\ProcSniperCanary", FileName: "~canary_user_settings.ini", Extension: ".ini"},
}

// CreateCanaryFile creates a honeypot file with known low entropy content
// The content is realistic-looking but meaningless (decoy data)
func CreateCanaryFile(filePath string, extension string, size int64) error {
	// Create parent directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create canary directory: %w", err)
	}

	// Generate content based on file type
	var content []byte

	switch extension {
	case ".txt":
		content = generateTextCanary(size)
	case ".xlsx", ".docx", ".pdf":
		// For binary formats, use low-entropy structured data
		content = generateBinaryCanary(size)
	case ".jpg", ".png":
		// For images, use simple patterns (low entropy)
		content = generateImageCanary(size)
	case ".xml":
		content = generateXMLCanary(size)
	case ".ini":
		content = generateINICanary(size)
	case ".dat", ".bin":
		// Binary data files with structured low-entropy patterns
		content = generateBinaryCanary(size)
	default:
		content = generateTextCanary(size)
	}

	// Write canary file
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("failed to write canary file: %w", err)
	}

	return nil
}

// generateTextCanary creates realistic-looking text with LOW entropy
// Uses repetitive patterns to ensure entropy stays around 4.0-5.0 bits/byte
func generateTextCanary(size int64) []byte {
	// Repetitive text pattern (low entropy)
	pattern := []byte("This is a sample document containing important financial information. " +
		"All data is confidential and should not be shared. " +
		"Tax returns, invoices, and financial summaries are stored here. " +
		"Please backup regularly to prevent data loss. ")

	content := make([]byte, 0, size)
	for int64(len(content)) < size {
		content = append(content, pattern...)
	}

	// Trim to exact size
	if int64(len(content)) > size {
		content = content[:size]
	}

	return content
}

// generateBinaryCanary creates structured binary data with LOW entropy
// Uses repetitive patterns to mimic Office/PDF structure
func generateBinaryCanary(size int64) []byte {
	// Office files have headers + repetitive XML/structure
	// Use simple repeating pattern for low entropy
	pattern := []byte{
		0x50, 0x4B, 0x03, 0x04, // ZIP header (Office files are ZIP-based)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	content := make([]byte, 0, size)
	for int64(len(content)) < size {
		content = append(content, pattern...)
	}

	if int64(len(content)) > size {
		content = content[:size]
	}

	return content
}

// generateImageCanary creates simple image-like data with LOW entropy
// Uses solid color blocks (highly repetitive = low entropy)
func generateImageCanary(size int64) []byte {
	// Simple BMP-like header + solid color pattern
	pattern := []byte{
		0xFF, 0xFF, 0xFF, // White pixel (RGB)
		0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF,
	}

	content := make([]byte, 0, size)
	for int64(len(content)) < size {
		content = append(content, pattern...)
	}

	if int64(len(content)) > size {
		content = content[:size]
	}

	return content
}

// GenerateSecureRandomBytes generates cryptographically secure random bytes
// Used for creating high-entropy test files (NOT for canaries)
func GenerateSecureRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// generateXMLCanary creates XML configuration file with LOW entropy
// Uses repetitive XML structure to maintain low entropy
func generateXMLCanary(size int64) []byte {
	// Repetitive XML pattern (low entropy)
	pattern := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <settings>
    <setting name="key1" value="value1"/>
    <setting name="key2" value="value2"/>
    <setting name="key3" value="value3"/>
  </settings>
  <data>
    <entry>Sample configuration data for system settings</entry>
    <entry>This is a decoy file for ransomware detection</entry>
  </data>
</configuration>
`)

	content := make([]byte, 0, size)
	for int64(len(content)) < size {
		content = append(content, pattern...)
	}

	if int64(len(content)) > size {
		content = content[:size]
	}

	return content
}

// generateINICanary creates INI configuration file with LOW entropy
// Uses repetitive INI structure common in Windows applications
func generateINICanary(size int64) []byte {
	// Repetitive INI pattern (low entropy)
	pattern := []byte(`[General]
AppName=Sample Application
Version=1.0.0
InstallPath=C:\Program Files\App

[Settings]
AutoUpdate=true
CheckInterval=3600
LogLevel=INFO

[Database]
Server=localhost
Port=5432
Database=appdb

[Security]
EnableEncryption=true
KeySize=256
`)

	content := make([]byte, 0, size)
	for int64(len(content)) < size {
		content = append(content, pattern...)
	}

	if int64(len(content)) > size {
		content = content[:size]
	}

	return content
}

// GetUserDirectory returns the path for a user directory (Documents, Desktop, etc.)
func GetUserDirectory(dirName string) (string, error) {
	// Get user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	// Construct full path
	fullPath := filepath.Join(homeDir, dirName)
	return fullPath, nil
}
