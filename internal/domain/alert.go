package domain

import (
	"strings"
	"time"
)

// Alert represents a threat detection alert
type Alert struct {
	ID              string
	Timestamp       time.Time
	Severity        ThreatLevel
	Category        string // "RANSOMWARE", "STEALER", "CREDENTIAL_THEFT"
	ProcessGuid     string
	ProcessID       int
	Image           string
	Description     string
	Score           int
	Indicators      []Indicator
	Evidence        map[string]interface{}
	AutoRespond     bool
	Responded       bool
	ResponseActions []string
}

// NewAlert creates a new detection alert
func NewAlert(category string, severity ThreatLevel, processGuid string, pid int, image string, description string, score int) *Alert {
	return &Alert{
		ID:              generateAlertID(),
		Timestamp:       time.Now(),
		Severity:        severity,
		Category:        category,
		ProcessGuid:     processGuid,
		ProcessID:       pid,
		Image:           image,
		Description:     description,
		Score:           score,
		Indicators:      make([]Indicator, 0),
		Evidence:        make(map[string]interface{}),
		AutoRespond:     false,
		Responded:       false,
		ResponseActions: make([]string, 0),
	}
}

// AddIndicator adds a threat indicator to the alert
func (a *Alert) AddIndicator(indicator Indicator) {
	a.Indicators = append(a.Indicators, indicator)
}

// AddEvidence adds evidence to the alert
func (a *Alert) AddEvidence(key string, value interface{}) {
	a.Evidence[key] = value
}

// AddResponseAction records an automated response action
func (a *Alert) AddResponseAction(action string) {
	a.ResponseActions = append(a.ResponseActions, action)
	a.Responded = true
}

// ShouldEscalate determines if alert should be escalated to analyst
func (a *Alert) ShouldEscalate() bool {
	return a.Severity == ThreatHigh || a.Severity == ThreatCritical
}

// generateAlertID generates a unique alert ID
func generateAlertID() string {
	return time.Now().Format("20060102150405") + "-" + generateRandomString(8)
}

// generateRandomString generates a random alphanumeric string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// DetectionContext provides context for detection decisions
type DetectionContext struct {
	Timestamp         time.Time
	ProcessGuid       string
	ProcessID         int
	Image             string
	CommandLine       string
	ParentProcessGuid string
	ParentImage       string
	User              string
}

// SysmonEvent represents a parsed Sysmon event
type SysmonEvent struct {
	EventID       int
	Timestamp     time.Time
	Computer      string
	ProcessGuid   string
	ProcessID     int
	Image         string
	CommandLine   string
	TargetFile    string
	TargetImage   string
	GrantedAccess string
	RawXML        string
}

// IsRansomwareExtension checks if file extension matches known ransomware patterns (case-insensitively)
func IsRansomwareExtension(filename string, extensions []string) bool {
	// Convert the entire filename to lowercase
	lowerFilename := strings.ToLower(filename)

	for _, ext := range extensions {
		// Use strings.HasSuffix for a cleaner and more readable check
		// This checks if lowerFilename ends with ext
		if strings.HasSuffix(lowerFilename, ext) {
			return true
		}
	}
	return false
}

// RansomNoteFilenames are common ransom note filenames
var RansomNoteFilenames = []string{
	"README.txt",
	"README.TXT",
	"READ_ME.txt",
	"DECRYPT.txt",
	"HOW_TO_DECRYPT.txt",
	"RECOVERY.txt",
	"FILES_ENCRYPTED.txt",
	"YOUR_FILES_ARE_ENCRYPTED.txt",
	"HELP_DECRYPT.txt",
	"HELP_RESTORE_FILES.txt",
	"RESTORE_FILES.txt",
	"README-DECRYPT.txt",
	"HELP_ME_UNLOCK.txt",
	"HOW_TO_RECOVER_FILES.txt",
	"_readme.txt",
	"_DECRYPT_FILES.txt",
	"readme.txt", // lowercase variants
	"decrypt.txt",
	"how_to_decrypt.txt",
}

// IsRansomNote checks if filename matches known ransom note patterns
func IsRansomNote(filename string) bool {
	// Extract just the filename from full path
	lastSlash := -1
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '\\' || filename[i] == '/' {
			lastSlash = i
			break
		}
	}

	baseName := filename
	if lastSlash != -1 {
		baseName = filename[lastSlash+1:]
	}

	// Case-insensitive comparison
	baseNameLower := ""
	for _, c := range baseName {
		if c >= 'A' && c <= 'Z' {
			baseNameLower += string(c + 32)
		} else {
			baseNameLower += string(c)
		}
	}

	for _, note := range RansomNoteFilenames {
		noteLower := ""
		for _, c := range note {
			if c >= 'A' && c <= 'Z' {
				noteLower += string(c + 32)
			} else {
				noteLower += string(c)
			}
		}

		if baseNameLower == noteLower {
			return true
		}
	}
	return false
}

// SuspiciousCommandPatterns are command patterns indicating malicious activity
var SuspiciousCommandPatterns = map[string]string{
	//	"vssadmin delete shadows":                   "Shadow copy deletion",
	//	"wmic shadowcopy delete":                    "Shadow copy deletion",
	//	"bcdedit /set {default} recoveryenabled No": "Recovery disable",
	//	"wbadmin delete catalog":                    "Backup deletion",
	//	"sekurlsa::logonpasswords":                  "Mimikatz credential dump",
	//	"sekurlsa::minidump":                        "Mimikatz credential dump",
	//	"procdump -ma lsass":                        "LSASS dump",
	//	"rundll32 comsvcs.dll MiniDump":             "LSASS dump",
}

// BrowserCredentialPaths are paths to browser credential stores
var BrowserCredentialPaths = []string{
	`\Google\Chrome\User Data\Default\Login Data`,
	`\Microsoft\Edge\User Data\Default\Login Data`,
	`\BraveSoftware\Brave-Browser\User Data\Default\Login Data`,
	`\Mozilla\Firefox\Profiles\`,
	`\logins.json`,
	`\key4.db`,
	`\Cookies`,
	`\Web Data`,
	`\Local State`,
}
