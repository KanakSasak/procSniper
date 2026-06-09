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
		name          string
		fileCount     int
		expectedTier  VelocityTier
		expectedLevel string
		description   string
	}{
		{
			name:          "Low velocity",
			fileCount:     5,
			expectedTier:  VelocityTierNone,
			expectedLevel: "NONE",
			description:   "5 files in 60s = 5 files/min",
		},
		{
			name:          "Monitor velocity",
			fileCount:     15,
			expectedTier:  VelocityTierMonitor,
			expectedLevel: "MONITOR",
			description:   "15 files in 60s = 15 files/min (10-29 monitor)",
		},
		{
			name:          "Analyze velocity",
			fileCount:     55,
			expectedTier:  VelocityTierAnalyze,
			expectedLevel: "ANALYZE",
			description:   "55 files in 60s = 55 files/min (30-99 analyze)",
		},
		{
			name:          "Critical velocity - ransomware",
			fileCount:     105,
			expectedTier:  VelocityTierCritical,
			expectedLevel: "CRITICAL",
			description:   "105 files in 60s = 105 files/min (>=100 ransomware)",
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

			tier, velocity, level := tracker.DetectAnomalousActivity(processGuid)

			if tier != tt.expectedTier {
				t.Errorf("Tier = %v, expected %v (velocity: %.2f)",
					tier, tt.expectedTier, velocity)
			}

			if level != tt.expectedLevel {
				t.Errorf("Level = %s, expected %s", level, tt.expectedLevel)
			}

			t.Logf("%s - Velocity: %.2f files/min, Level: %s",
				tt.description, velocity, level)
		})
	}
}

func TestFileOperationTracker_SetThresholds(t *testing.T) {
	const processGuid = "{set-thresholds-guid}"
	addOps := func(tr *FileOperationTracker, n int) {
		for i := 0; i < n; i++ {
			tr.AddOperation(FileOperation{
				Timestamp:   time.Now(),
				ProcessGuid: processGuid,
				Operation:   "create",
			})
		}
	}

	// 60 files/min with default thresholds (10/30/100) is ANALYZE, not CRITICAL.
	def := NewFileOperationTracker(60 * time.Second)
	addOps(def, 60)
	if tier, _, _ := def.DetectAnomalousActivity(processGuid); tier != VelocityTierAnalyze {
		t.Errorf("default: 60 files/min tier = %v, expected ANALYZE", tier)
	}

	// Lowering the critical threshold to 50 must reclassify the same load as CRITICAL —
	// this is the io_velocity_threshold_per_minute config wiring at the domain level.
	tuned := NewFileOperationTracker(60 * time.Second)
	tuned.SetThresholds(0, 0, 50) // only critical overridden; monitor/analyze keep defaults
	addOps(tuned, 60)
	if tier, _, _ := tuned.DetectAnomalousActivity(processGuid); tier != VelocityTierCritical {
		t.Errorf("tuned critical=50: 60 files/min tier = %v, expected CRITICAL", tier)
	}

	// Non-positive overrides are ignored so an unset/zero config key can't zero a tier.
	keep := NewFileOperationTracker(60 * time.Second)
	keep.SetThresholds(-1, 0, 0)
	addOps(keep, 60)
	if tier, _, _ := keep.DetectAnomalousActivity(processGuid); tier != VelocityTierAnalyze {
		t.Errorf("ignored overrides: 60 files/min tier = %v, expected ANALYZE", tier)
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
