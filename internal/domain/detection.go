package domain

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

// EntropyThresholds define file-type specific entropy thresholds
var EntropyThresholds = map[string]float64{
	".txt":  7.5,
	".doc":  7.5,
	".xls":  7.5,
	".docx": 7.9, // Already compressed
	".xlsx": 7.9,
	".pdf":  7.9,
	".jpg":  7.95,
	".png":  7.95,
	".exe":  7.8,
	"":      7.5, // Default threshold
}

// CalculateShannonEntropy calculates Shannon entropy for byte data
// Entropy near 8.0 indicates encrypted/compressed data
// Normal text files range from 4.5-5.5 bits per byte
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count byte frequencies
	frequencies := make([]int, 256)
	for _, b := range data {
		frequencies[b]++
	}

	// Calculate entropy: H(X) = -Σ(p(xi) * log2(p(xi)))
	entropy := 0.0
	dataLen := float64(len(data))

	for _, freq := range frequencies {
		if freq > 0 {
			probability := float64(freq) / dataLen
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// IsLikelyEncrypted analyzes a file to determine if it's encrypted
// Uses sliding-window entropy analysis on first 8KB
// Enhanced: Uses Windows API with FILE_SHARE_READ|FILE_SHARE_WRITE to read locked files
func IsLikelyEncrypted(filePath string, originalExtension string) (bool, float64, error) {
	// Use Windows API opener that can read locked files
	file, err := openFileForEntropy(filePath)
	if err != nil {
		return false, 0, err
	}
	defer file.Close()

	// Read first 8KB for analysis
	buffer := make([]byte, 8192)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return false, 0, err
	}

	if n == 0 {
		return false, 0, nil
	}

	entropy := CalculateShannonEntropy(buffer[:n])

	// Get threshold for file type
	threshold, exists := EntropyThresholds[originalExtension]
	if !exists {
		threshold = EntropyThresholds[""]
	}

	return entropy >= threshold, entropy, nil
}

// FileEntropy represents entropy analysis result
type FileEntropy struct {
	FilePath          string
	Entropy           float64
	Threshold         float64
	IsLikelyEncrypted bool
	FileSize          int64
}

// AnalyzeFileEntropy performs comprehensive entropy analysis
func AnalyzeFileEntropy(filePath string, extension string) (*FileEntropy, error) {
	isEncrypted, entropy, err := IsLikelyEncrypted(filePath, extension)
	if err != nil {
		return nil, err
	}

	threshold := EntropyThresholds[extension]
	if threshold == 0 {
		threshold = EntropyThresholds[""]
	}

	fileInfo, err := os.Stat(filePath)
	var fileSize int64
	if err == nil {
		fileSize = fileInfo.Size()
	}

	return &FileEntropy{
		FilePath:          filePath,
		Entropy:           entropy,
		Threshold:         threshold,
		IsLikelyEncrypted: isEncrypted,
		FileSize:          fileSize,
	}, nil
}

// AnalyzeFileEntropyWithRetry performs entropy analysis with retry logic for locked files
// This is critical for detecting in-place encryption where ransomware may still have the file locked
func AnalyzeFileEntropyWithRetry(filePath string, extension string, maxRetries int, delay time.Duration) (*FileEntropy, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		entropy, err := AnalyzeFileEntropy(filePath, extension)

		if err == nil {
			return entropy, nil
		}

		// Check if error is due to file being locked/access denied
		if isFileLocked(err) {
			lastErr = err
			// Exponential backoff: delay * (attempt + 1)
			sleepDuration := delay * time.Duration(attempt+1)
			time.Sleep(sleepDuration)
			continue
		}

		// Other error (file not found, permission permanently denied, etc.)
		return nil, err
	}

	return nil, fmt.Errorf("file locked after %d retries: %w", maxRetries, lastErr)
}

// isFileLocked checks if the error is due to file being locked or access denied
func isFileLocked(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	// Windows error messages for locked files
	lockedIndicators := []string{
		"The process cannot access the file",
		"being used by another process",
		"Access is denied",
		"sharing violation",
	}

	for _, indicator := range lockedIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}

	return false
}
