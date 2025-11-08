package domain

import (
	"testing"
	"time"
)

func TestFileOperationTracker_AddOperation(t *testing.T) {
	tracker := NewFileOperationTracker(60 * time.Second)

	op := FileOperation{
		Timestamp:   time.Now(),
		ProcessGuid: "{12345678-1234-1234-1234-123456789012}",
		ProcessID:   1234,
		Operation:   "create",
		FilePath:    "C:\\test\\file.txt",
		Image:       "C:\\malware\\ransomware.exe",
	}

	tracker.AddOperation(op)

	count := tracker.GetOperationCount(op.ProcessGuid)
	if count != 1 {
		t.Errorf("Operation count = %d, expected 1", count)
	}
}

func TestFileOperationTracker_DetectAnomalousActivity(t *testing.T) {
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	tests := []struct {
		name           string
		fileCount      int
		expectedSusp   bool
		expectedLevel  string
		description    string
	}{
		{
			name:          "Low velocity",
			fileCount:     5,
			expectedSusp:  false,
			expectedLevel: "NONE",
			description:   "5 files in 60s = 5 files/min",
		},
		{
			name:          "Medium velocity",
			fileCount:     55,
			expectedSusp:  false,
			expectedLevel: "MEDIUM",
			description:   "55 files in 60s = 55 files/min (suspicious)",
		},
		{
			name:          "High velocity - ransomware",
			fileCount:     105,
			expectedSusp:  true,
			expectedLevel: "HIGH",
			description:   "105 files in 60s = 105 files/min (ransomware)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewFileOperationTracker(60 * time.Second)

			// Add operations
			for i := 0; i < tt.fileCount; i++ {
				op := FileOperation{
					Timestamp:   time.Now(),
					ProcessGuid: processGuid,
					ProcessID:   1234,
					Operation:   "create",
					FilePath:    "C:\\test\\file" + string(rune(i)) + ".txt",
					Image:       "C:\\malware\\ransomware.exe",
				}
				tracker.AddOperation(op)
			}

			suspicious, velocity, level := tracker.DetectAnomalousActivity(processGuid)

			if suspicious != tt.expectedSusp {
				t.Errorf("Suspicious = %v, expected %v (velocity: %.2f)",
					suspicious, tt.expectedSusp, velocity)
			}

			if level != tt.expectedLevel {
				t.Errorf("Level = %s, expected %s", level, tt.expectedLevel)
			}

			t.Logf("%s - Velocity: %.2f files/min, Level: %s",
				tt.description, velocity, level)
		})
	}
}

func TestFileOperationTracker_SlidingWindow(t *testing.T) {
	tracker := NewFileOperationTracker(2 * time.Second) // 2 second window for testing
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Add operation at t=0
	op1 := FileOperation{
		Timestamp:   time.Now(),
		ProcessGuid: processGuid,
		ProcessID:   1234,
		Operation:   "create",
		FilePath:    "C:\\test\\file1.txt",
		Image:       "C:\\test.exe",
	}
	tracker.AddOperation(op1)

	count := tracker.GetOperationCount(processGuid)
	if count != 1 {
		t.Errorf("Initial count = %d, expected 1", count)
	}

	// Wait for window to expire
	time.Sleep(3 * time.Second)

	// Add new operation at t=3
	op2 := FileOperation{
		Timestamp:   time.Now(),
		ProcessGuid: processGuid,
		ProcessID:   1234,
		Operation:   "create",
		FilePath:    "C:\\test\\file2.txt",
		Image:       "C:\\test.exe",
	}
	tracker.AddOperation(op2)

	// First operation should be expired
	count = tracker.GetOperationCount(processGuid)
	if count != 1 {
		t.Errorf("Count after expiry = %d, expected 1 (old operation should be removed)", count)
	}
}

func TestFileOperationTracker_GetOperationsByType(t *testing.T) {
	tracker := NewFileOperationTracker(60 * time.Second)
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Add different operation types
	operations := []string{"create", "create", "create", "delete", "modify"}
	for i, opType := range operations {
		op := FileOperation{
			Timestamp:   time.Now(),
			ProcessGuid: processGuid,
			ProcessID:   1234,
			Operation:   opType,
			FilePath:    "C:\\test\\file" + string(rune(i)) + ".txt",
			Image:       "C:\\test.exe",
		}
		tracker.AddOperation(op)
	}

	counts := tracker.GetOperationsByType(processGuid)

	if counts["create"] != 3 {
		t.Errorf("Create count = %d, expected 3", counts["create"])
	}
	if counts["delete"] != 1 {
		t.Errorf("Delete count = %d, expected 1", counts["delete"])
	}
	if counts["modify"] != 1 {
		t.Errorf("Modify count = %d, expected 1", counts["modify"])
	}

	t.Logf("Operation counts: %v", counts)
}

func TestFileOperationTracker_Cleanup(t *testing.T) {
	tracker := NewFileOperationTracker(1 * time.Second) // 1 second window
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Add 10 operations
	for i := 0; i < 10; i++ {
		op := FileOperation{
			Timestamp:   time.Now(),
			ProcessGuid: processGuid,
			ProcessID:   1234,
			Operation:   "create",
			FilePath:    "C:\\test\\file" + string(rune(i)) + ".txt",
			Image:       "C:\\test.exe",
		}
		tracker.AddOperation(op)
	}

	count := tracker.GetOperationCount(processGuid)
	if count != 10 {
		t.Errorf("Initial count = %d, expected 10", count)
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Run cleanup
	removed := tracker.Cleanup()
	if removed != 10 {
		t.Errorf("Removed = %d, expected 10", removed)
	}

	count = tracker.GetOperationCount(processGuid)
	if count != 0 {
		t.Errorf("Count after cleanup = %d, expected 0", count)
	}
}

func BenchmarkFileOperationTracker_AddOperation(b *testing.B) {
	tracker := NewFileOperationTracker(60 * time.Second)
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		op := FileOperation{
			Timestamp:   time.Now(),
			ProcessGuid: processGuid,
			ProcessID:   1234,
			Operation:   "create",
			FilePath:    "C:\\test\\file.txt",
			Image:       "C:\\test.exe",
		}
		tracker.AddOperation(op)
	}
}

func BenchmarkFileOperationTracker_DetectAnomalousActivity(b *testing.B) {
	tracker := NewFileOperationTracker(60 * time.Second)
	processGuid := "{12345678-1234-1234-1234-123456789012}"

	// Pre-populate with operations
	for i := 0; i < 100; i++ {
		op := FileOperation{
			Timestamp:   time.Now(),
			ProcessGuid: processGuid,
			ProcessID:   1234,
			Operation:   "create",
			FilePath:    "C:\\test\\file.txt",
			Image:       "C:\\test.exe",
		}
		tracker.AddOperation(op)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tracker.DetectAnomalousActivity(processGuid)
	}
}
