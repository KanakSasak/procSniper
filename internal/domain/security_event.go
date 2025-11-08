package domain

import "time"

// SecurityEvent represents a Windows Security Log event
// Used for detecting privilege escalation and backup API usage
type SecurityEvent struct {
	EventID     int
	Timestamp   time.Time
	ProcessName string
	ProcessID   string
	UserName    string
	Privileges  string
	ObjectName  string // For Event ID 4674 - target file/object
}

// IsBackupPrivilege checks if the event contains backup/restore privileges
func (se *SecurityEvent) IsBackupPrivilege() bool {
	return containsBackupPrivilege(se.Privileges)
}

// IsRestorePrivilege checks if the event contains restore privileges
func (se *SecurityEvent) IsRestorePrivilege() bool {
	return containsRestorePrivilege(se.Privileges)
}

// Helper functions
func containsBackupPrivilege(privileges string) bool {
	return contains(privileges, "SeBackupPrivilege")
}

func containsRestorePrivilege(privileges string) bool {
	return contains(privileges, "SeRestorePrivilege")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s != "" && substr != "" && findInString(s, substr)
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
