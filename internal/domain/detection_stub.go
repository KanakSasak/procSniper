//go:build !windows

package domain

import (
	"fmt"
	"os"
)

// openFileForEntropy opens a file for entropy analysis
// Non-Windows stub: Uses standard os.Open (no special share modes)
func openFileForEntropy(filePath string) (*os.File, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}
	return file, nil
}

// OpenFileShared is not available on non-Windows platforms
func OpenFileShared(filePath string) (*os.File, error) {
	return nil, fmt.Errorf("OpenFileShared is only available on Windows")
}

// ReadFileWithRetry is not available on non-Windows platforms
func ReadFileWithRetry(filePath string, maxBytes int, maxRetries int) ([]byte, error) {
	return nil, fmt.Errorf("ReadFileWithRetry is only available on Windows")
}
