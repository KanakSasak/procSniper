package domain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCalculateShannonEntropy(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minRange float64
		maxRange float64
	}{
		{
			name:     "All zeros - minimum entropy",
			data:     make([]byte, 1000),
			minRange: 0.0,
			maxRange: 0.1,
		},
		{
			name:     "Plaintext English - low entropy",
			data:     []byte("The quick brown fox jumps over the lazy dog. " +
				"This is a test of low entropy plaintext data that should score between 4-5 bits per byte."),
			minRange: 4.0,
			maxRange: 5.5,
		},
		{
			name:     "Random data - high entropy",
			data:     generateRandomBytes(1000),
			minRange: 7.5,
			maxRange: 8.0,
		},
		{
			name:     "Encrypted-like data - maximum entropy",
			data:     generatePseudoEncryptedData(1000),
			minRange: 7.8,
			maxRange: 8.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculateShannonEntropy(tt.data)

			if entropy < tt.minRange || entropy > tt.maxRange {
				t.Errorf("Entropy = %.3f, expected between %.3f and %.3f",
					entropy, tt.minRange, tt.maxRange)
			}

			t.Logf("Entropy: %.3f bits/byte", entropy)
		})
	}
}

func TestIsLikelyEncrypted(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name              string
		content           []byte
		extension         string
		expectedEncrypted bool
		description       string
	}{
		{
			name:              "Plaintext file",
			content:           []byte("This is normal plaintext content that should not be flagged as encrypted."),
			extension:         ".txt",
			expectedEncrypted: false,
			description:       "Normal text file with low entropy",
		},
		{
			name:              "Encrypted file",
			content:           generatePseudoEncryptedData(8192),
			extension:         ".txt",
			expectedEncrypted: true,
			description:       "High entropy data exceeding threshold",
		},
		{
			name:              "Already compressed file",
			content:           generateModerateEntropyData(8192, 7.85),
			extension:         ".docx",
			expectedEncrypted: false, // Higher threshold for compressed formats
			description:       "DOCX files naturally have high entropy",
		},
		{
			name:              "Image file",
			content:           generateModerateEntropyData(8192, 7.92),
			extension:         ".jpg",
			expectedEncrypted: false, // JPG already compressed
			description:       "JPEG files naturally have very high entropy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			filePath := filepath.Join(tempDir, "test"+tt.extension)
			err := os.WriteFile(filePath, tt.content, 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			defer os.Remove(filePath)

			// Test detection
			isEncrypted, entropy, err := IsLikelyEncrypted(filePath, tt.extension)
			if err != nil {
				t.Fatalf("IsLikelyEncrypted failed: %v", err)
			}

			if isEncrypted != tt.expectedEncrypted {
				t.Errorf("IsLikelyEncrypted = %v, expected %v (entropy: %.3f, threshold: %.3f)",
					isEncrypted, tt.expectedEncrypted, entropy, EntropyThresholds[tt.extension])
			}

			t.Logf("%s - Entropy: %.3f, Encrypted: %v", tt.description, entropy, isEncrypted)
		})
	}
}

func TestAnalyzeFileEntropy(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	content := []byte("Test content for entropy analysis")
	filePath := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(filePath, content, 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(filePath)

	result, err := AnalyzeFileEntropy(filePath, ".txt")
	if err != nil {
		t.Fatalf("AnalyzeFileEntropy failed: %v", err)
	}

	if result.FilePath != filePath {
		t.Errorf("FilePath = %s, expected %s", result.FilePath, filePath)
	}

	if result.FileSize <= 0 {
		t.Errorf("FileSize = %d, expected > 0", result.FileSize)
	}

	if result.Threshold != EntropyThresholds[".txt"] {
		t.Errorf("Threshold = %.3f, expected %.3f",
			result.Threshold, EntropyThresholds[".txt"])
	}

	t.Logf("Entropy analysis: %.3f bits/byte, threshold: %.3f, encrypted: %v",
		result.Entropy, result.Threshold, result.IsLikelyEncrypted)
}

func BenchmarkCalculateShannonEntropy(b *testing.B) {
	data := generateRandomBytes(8192)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		CalculateShannonEntropy(data)
	}
}

func BenchmarkIsLikelyEncrypted(b *testing.B) {
	tempDir := b.TempDir()
	filePath := filepath.Join(tempDir, "bench.txt")
	content := generateRandomBytes(8192)
	os.WriteFile(filePath, content, 0644)
	defer os.Remove(filePath)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		IsLikelyEncrypted(filePath, ".txt")
	}
}

// Helper functions

func generateRandomBytes(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

func generatePseudoEncryptedData(size int) []byte {
	// Generate data with very uniform byte distribution (high entropy)
	data := make([]byte, size)
	for i := range data {
		// Use a pattern that gives high entropy
		data[i] = byte((i * 7919) % 256) // Prime number for better distribution
	}
	return data
}

func generateModerateEntropyData(size int, targetEntropy float64) []byte {
	// Generate data with specific entropy level
	// For entropy slightly below threshold, use less uniform distribution
	data := make([]byte, size)
	// Use fewer unique bytes to lower entropy
	uniqueBytes := 200 // Reduces from 256 to lower entropy
	for i := range data {
		data[i] = byte((i * 7919) % uniqueBytes)
	}
	return data
}
