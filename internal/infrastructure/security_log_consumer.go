//go:build windows

package infrastructure

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"procSniper/config"
	"procSniper/internal/domain"

	"golang.org/x/sys/windows"
)

// Windows Security Event IDs for privilege detection
const (
	EventIDPrivilegeUse      = 4672 // Special privileges assigned to new logon
	EventIDTokenAdjusted     = 4703 // Token privileges adjusted (process enables SeBackupPrivilege)
	EventIDPrivilegedService = 4674 // Privileged operation attempted
)

// SecurityEventProcessor is an interface for processing Windows Security events
type SecurityEventProcessor interface {
	ProcessBackupPrivilege(ctx context.Context, event *domain.SecurityEvent)
}

// SecurityLogConsumer reads Windows Security Event Log for privilege escalation detection
type SecurityLogConsumer struct {
	eventProcessor SecurityEventProcessor
	config         *config.Config
	running        bool
	stopChan       chan struct{}
}

// NewSecurityLogConsumer creates a new Windows Security Log consumer
func NewSecurityLogConsumer(processor SecurityEventProcessor, cfg *config.Config) *SecurityLogConsumer {
	return &SecurityLogConsumer{
		eventProcessor: processor,
		config:         cfg,
		stopChan:       make(chan struct{}),
	}
}

// Start begins consuming Windows Security events
func (slc *SecurityLogConsumer) Start(ctx context.Context) error {
	log.Println("[SECURITY] Starting Windows Security Event Log monitoring...")
	log.Println("[SECURITY] Monitoring for SeBackupPrivilege/SeRestorePrivilege usage...")

	slc.running = true
	go slc.subscribeToSecurityEvents(ctx)

	return nil
}

// Stop stops the security log consumer
func (slc *SecurityLogConsumer) Stop() {
	log.Println("[SECURITY] Stopping Windows Security Event Log monitoring...")
	slc.running = false
	close(slc.stopChan)
}

// subscribeToSecurityEvents subscribes to Windows Security event log
func (slc *SecurityLogConsumer) subscribeToSecurityEvents(ctx context.Context) {
	// XPath query to filter relevant Security events
	// Event IDs: 4672 (Special privileges), 4703 (Token adjusted)
	query := "*[System[(EventID=4672 or EventID=4703 or EventID=4674)]]"
	channelPath := "Security"

	log.Printf("[SECURITY] Subscribing to Security event log...")
	log.Printf("[SECURITY] Query: %s\n", query)

	// Convert to UTF16
	queryPtr, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		log.Printf("[!] Failed to convert query: %v\n", err)
		return
	}

	channelPtr, err := syscall.UTF16PtrFromString(channelPath)
	if err != nil {
		log.Printf("[!] Failed to convert channel path: %v\n", err)
		return
	}

	// Subscribe to events (EvtSubscribeToFutureEvents = 1)
	subscription, err := evtSubscribe(
		0,          // Session (NULL for local)
		0,          // SignalEvent (NULL)
		channelPtr, // Channel path
		queryPtr,   // Query
		0,          // Bookmark (NULL)
		0,          // Context
		0,          // Callback (NULL, we'll use pull mode)
		1,          // EvtSubscribeToFutureEvents
	)

	if err != nil {
		log.Printf("[!] Failed to subscribe to Security events: %v\n", err)
		log.Printf("[!] NOTE: Requires Administrator privileges and Security log access\n")
		return
	}
	defer windows.CloseHandle(subscription)

	log.Println("[SECURITY] ✓ Successfully subscribed to Windows Security Event Log")
	log.Println("[SECURITY] Monitoring for backup privilege usage (SeBackupPrivilege/SeRestorePrivilege)...")

	// Event buffer
	var events [10]windows.Handle
	var returned uint32

	for {
		select {
		case <-ctx.Done():
			log.Println("[SECURITY] Context cancelled, stopping Security log monitoring")
			return
		case <-slc.stopChan:
			log.Println("[SECURITY] Stop signal received")
			return
		default:
			// Pull events from subscription (1 second timeout)
			success := evtNext(
				subscription,
				uint32(len(events)),
				&events[0],
				1000, // 1 second timeout
				0,
				&returned,
			)

			if !success {
				errno := windows.GetLastError()
				if errno == syscall.Errno(ERROR_NO_MORE_ITEMS) || errno == syscall.Errno(ERROR_TIMEOUT) {
					// No events available, continue polling
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Printf("[!] EvtNext failed: %v\n", errno)
				time.Sleep(1 * time.Second)
				continue
			}

			// Process retrieved events
			for i := uint32(0); i < returned; i++ {
				slc.processSecurityEvent(ctx, events[i])
				windows.CloseHandle(events[i])
			}
		}
	}
}

// processSecurityEvent processes a single Windows Security event
func (slc *SecurityLogConsumer) processSecurityEvent(ctx context.Context, eventHandle windows.Handle) {
	// Render event as XML
	xmlText, err := renderEventAsXML(eventHandle)
	if err != nil {
		log.Printf("[!] Failed to render Security event: %v\n", err)
		return
	}

	// Verbose logging: log raw XML
	if slc.config.EnableDetailedLogs {
		log.Printf("[SECURITY] [VERBOSE] Raw event XML length: %d bytes\n", len(xmlText))
		log.Printf("[SECURITY] [VERBOSE] Raw XML:\n%s\n", xmlText)
	}

	// Parse XML
	var securityEvent SecurityEventXML
	if err := xml.Unmarshal([]byte(xmlText), &securityEvent); err != nil {
		log.Printf("[!] Failed to parse Security event XML: %v\n", err)
		return
	}

	// Verbose logging: log parsed event details
	if slc.config.EnableDetailedLogs {
		log.Printf("[SECURITY] [VERBOSE] Parsed Event ID: %d\n", securityEvent.System.EventID)
		log.Printf("[SECURITY] [VERBOSE] Event data fields: %d\n", len(securityEvent.EventData.Data))
	}

	// Extract process information and privileges
	eventID := securityEvent.System.EventID

	switch eventID {
	case EventIDPrivilegeUse: // 4672 - Special privileges assigned
		slc.processPrivilegeAssignment(ctx, &securityEvent)
	case EventIDTokenAdjusted: // 4703 - Token privileges adjusted
		slc.processTokenAdjustment(ctx, &securityEvent)
	case EventIDPrivilegedService: // 4674 - Privileged operation attempted
		slc.processPrivilegedOperation(ctx, &securityEvent)
	}
}

// processPrivilegeAssignment handles Event ID 4672 (Special privileges assigned)
func (slc *SecurityLogConsumer) processPrivilegeAssignment(ctx context.Context, event *SecurityEventXML) {
	privileges := extractPrivileges(event.EventData.Data)

	// Verbose logging: log all extracted data
	if slc.config.EnableDetailedLogs {
		log.Printf("[SECURITY] [VERBOSE] Event 4672 - All event data:\n")
		for _, data := range event.EventData.Data {
			log.Printf("[SECURITY] [VERBOSE]   %s: %s\n", data.Name, data.Value)
		}
	}

	// Check for backup/restore privileges
	if strings.Contains(privileges, "SeBackupPrivilege") || strings.Contains(privileges, "SeRestorePrivilege") {
		subjectUserName := extractDataValue(event.EventData.Data, "SubjectUserName")
		subjectDomainName := extractDataValue(event.EventData.Data, "SubjectDomainName")

		log.Printf("[SECURITY] 🚨 BACKUP PRIVILEGE ASSIGNED: User %s\\%s", subjectDomainName, subjectUserName)
		log.Printf("[SECURITY] 🚨 Privileges: %s", privileges)
		log.Printf("[SECURITY] 🚨 Event ID: 4672 (Special Privileges Assigned)")
		log.Printf("[SECURITY] 🚨 WARNING: Process may use BackupWrite to bypass Sysmon Event ID 11!")

		// Verbose logging: BackupRead/BackupWrite API details
		if slc.config.EnableDetailedLogs {
			log.Printf("[SECURITY] [VERBOSE] BackupRead API: Can read files bypassing NTFS permissions\n")
			log.Printf("[SECURITY] [VERBOSE] BackupWrite API: Can write files bypassing NTFS permissions and Sysmon Event ID 11\n")
			log.Printf("[SECURITY] [VERBOSE] SeBackupPrivilege detected: %v\n", strings.Contains(privileges, "SeBackupPrivilege"))
			log.Printf("[SECURITY] [VERBOSE] SeRestorePrivilege detected: %v\n", strings.Contains(privileges, "SeRestorePrivilege"))
		}

		// Create security event for detection service
		domainEvent := &domain.SecurityEvent{
			EventID:     4672,
			Timestamp:   time.Now(),
			ProcessName: "SYSTEM", // 4672 is system-level event
			UserName:    fmt.Sprintf("%s\\%s", subjectDomainName, subjectUserName),
			Privileges:  privileges,
		}

		slc.eventProcessor.ProcessBackupPrivilege(ctx, domainEvent)
	}
}

// processTokenAdjustment handles Event ID 4703 (Token privileges adjusted)
func (slc *SecurityLogConsumer) processTokenAdjustment(ctx context.Context, event *SecurityEventXML) {
	privileges := extractPrivileges(event.EventData.Data)

	// Verbose logging: log all extracted data
	if slc.config.EnableDetailedLogs {
		log.Printf("[SECURITY] [VERBOSE] Event 4703 - All event data:\n")
		for _, data := range event.EventData.Data {
			log.Printf("[SECURITY] [VERBOSE]   %s: %s\n", data.Name, data.Value)
		}
	}

	// Check for backup/restore privileges
	if strings.Contains(privileges, "SeBackupPrivilege") || strings.Contains(privileges, "SeRestorePrivilege") {
		processName := extractDataValue(event.EventData.Data, "ProcessName")
		processID := extractDataValue(event.EventData.Data, "ProcessId")

		log.Printf("[SECURITY] 🚨 BACKUP PRIVILEGE ENABLED: Process %s (PID: %s)", processName, processID)
		log.Printf("[SECURITY] 🚨 Enabled Privileges: %s", privileges)
		log.Printf("[SECURITY] 🚨 Event ID: 4703 (Token Privileges Adjusted)")
		log.Printf("[SECURITY] 🚨 CRITICAL: Process can now use BackupRead/BackupWrite APIs!")
		log.Printf("[SECURITY] 🚨 This may bypass Sysmon Event ID 11 file creation detection!")

		// Verbose logging: BackupRead/BackupWrite API usage details
		if slc.config.EnableDetailedLogs {
			log.Printf("[SECURITY] [VERBOSE] Process token has been adjusted to enable backup privileges\n")
			log.Printf("[SECURITY] [VERBOSE] BackupRead API signature: BOOL BackupRead(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID*)\n")
			log.Printf("[SECURITY] [VERBOSE] BackupWrite API signature: BOOL BackupWrite(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID*)\n")
			log.Printf("[SECURITY] [VERBOSE] Process: %s (PID: %s)\n", processName, processID)
			log.Printf("[SECURITY] [VERBOSE] Threat: Process can read/write ANY file bypassing ACLs and Sysmon monitoring\n")
		}

		// Create security event for detection service
		domainEvent := &domain.SecurityEvent{
			EventID:     4703,
			Timestamp:   time.Now(),
			ProcessName: processName,
			ProcessID:   processID,
			Privileges:  privileges,
		}

		slc.eventProcessor.ProcessBackupPrivilege(ctx, domainEvent)
	}
}

// processPrivilegedOperation handles Event ID 4674 (Privileged operation attempted)
func (slc *SecurityLogConsumer) processPrivilegedOperation(ctx context.Context, event *SecurityEventXML) {
	privileges := extractPrivileges(event.EventData.Data)

	// Verbose logging: log all extracted data
	if slc.config.EnableDetailedLogs {
		log.Printf("[SECURITY] [VERBOSE] Event 4674 - All event data:\n")
		for _, data := range event.EventData.Data {
			log.Printf("[SECURITY] [VERBOSE]   %s: %s\n", data.Name, data.Value)
		}
	}

	// Check for backup/restore privileges
	if strings.Contains(privileges, "SeBackupPrivilege") || strings.Contains(privileges, "SeRestorePrivilege") {
		processName := extractDataValue(event.EventData.Data, "ProcessName")
		processID := extractDataValue(event.EventData.Data, "ProcessId")
		objectName := extractDataValue(event.EventData.Data, "ObjectName")
		objectType := extractDataValue(event.EventData.Data, "ObjectType")
		accessMask := extractDataValue(event.EventData.Data, "AccessMask")

		log.Printf("[SECURITY] 🚨 BACKUP API USAGE: Process %s (PID: %s)", processName, processID)
		log.Printf("[SECURITY] 🚨 Target: %s", objectName)
		log.Printf("[SECURITY] 🚨 Privilege Used: %s", privileges)
		log.Printf("[SECURITY] 🚨 Event ID: 4674 (Privileged Operation)")
		log.Printf("[SECURITY] 🚨 ALERT: BackupRead/BackupWrite API call detected!")

		// Verbose logging: Detailed BackupRead/BackupWrite API call information
		if slc.config.EnableDetailedLogs {
			log.Printf("[SECURITY] [VERBOSE] === BackupRead/BackupWrite API Call Detected ===\n")
			log.Printf("[SECURITY] [VERBOSE] Process: %s (PID: %s)\n", processName, processID)
			log.Printf("[SECURITY] [VERBOSE] Target Object: %s\n", objectName)
			log.Printf("[SECURITY] [VERBOSE] Object Type: %s\n", objectType)
			log.Printf("[SECURITY] [VERBOSE] Access Mask: %s\n", accessMask)
			log.Printf("[SECURITY] [VERBOSE] Privilege: %s\n", privileges)
			log.Printf("[SECURITY] [VERBOSE] \n")
			log.Printf("[SECURITY] [VERBOSE] API Call Context:\n")
			log.Printf("[SECURITY] [VERBOSE]   - BackupRead: Used to read file data/metadata bypassing security\n")
			log.Printf("[SECURITY] [VERBOSE]   - BackupWrite: Used to write file data/metadata bypassing security\n")
			log.Printf("[SECURITY] [VERBOSE]   - Evasion Technique: Bypasses Sysmon Event ID 11 (FileCreate)\n")
			log.Printf("[SECURITY] [VERBOSE]   - Security Impact: Can exfiltrate or modify files regardless of ACLs\n")
			log.Printf("[SECURITY] [VERBOSE]   - Detection Method: Windows Security Event ID 4674\n")
		}

		// Create security event for detection service
		domainEvent := &domain.SecurityEvent{
			EventID:     4674,
			Timestamp:   time.Now(),
			ProcessName: processName,
			ProcessID:   processID,
			Privileges:  privileges,
			ObjectName:  objectName,
		}

		slc.eventProcessor.ProcessBackupPrivilege(ctx, domainEvent)
	}
}

// SecurityEventXML represents Windows Security Event XML structure
type SecurityEventXML struct {
	System struct {
		EventID int `xml:"EventID"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// Helper functions to extract data from Security events
func extractPrivileges(data []struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}) string {
	for _, d := range data {
		if d.Name == "PrivilegeList" || d.Name == "EnabledPrivileges" {
			return d.Value
		}
	}
	return ""
}

func extractDataValue(data []struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}, name string) string {
	for _, d := range data {
		if d.Name == name {
			return d.Value
		}
	}
	return ""
}

// Windows API constants
const (
	ERROR_NO_MORE_ITEMS = 259
	ERROR_TIMEOUT       = 1460
)

// Windows Event Log API functions (these should already be defined in sysmon_consumer.go)
// If not, we'll need to add them here
func evtSubscribe(session, signalEvent uintptr, channelPath, query *uint16, bookmark, context uintptr, callback uintptr, flags uint32) (windows.Handle, error) {
	r1, _, err := procEvtSubscribe.Call(
		session,
		signalEvent,
		uintptr(unsafe.Pointer(channelPath)),
		uintptr(unsafe.Pointer(query)),
		bookmark,
		context,
		callback,
		uintptr(flags),
	)
	if r1 == 0 {
		return 0, err
	}
	return windows.Handle(r1), nil
}

func evtNext(subscription windows.Handle, eventsSize uint32, events *windows.Handle, timeout, flags uint32, returned *uint32) bool {
	r1, _, _ := procEvtNext.Call(
		uintptr(subscription),
		uintptr(eventsSize),
		uintptr(unsafe.Pointer(events)),
		uintptr(timeout),
		uintptr(flags),
		uintptr(unsafe.Pointer(returned)),
	)
	return r1 != 0
}

// renderEventAsXML renders a Windows event handle as XML string
func renderEventAsXML(eventHandle windows.Handle) (string, error) {
	// First call to get required buffer size
	var bufferSize uint32
	var bufferUsed uint32
	var propertyCount uint32

	ret1, _, err1 := procEvtRender.Call(
		0,                                       // Context (NULL for XML rendering)
		uintptr(eventHandle),                    // Event handle
		EvtRenderEventXml,                       // Flags
		uintptr(bufferSize),                     // BufferSize (0 to get required size)
		0,                                       // Buffer (NULL)
		uintptr(unsafe.Pointer(&bufferUsed)),    // BufferUsed (output)
		uintptr(unsafe.Pointer(&propertyCount)), // PropertyCount (output)
	)

	if ret1 == 0 && bufferUsed == 0 {
		return "", fmt.Errorf("EvtRender failed to get buffer size: %v", err1)
	}

	// Allocate buffer and render
	if bufferUsed > 0 {
		buffer := make([]uint16, bufferUsed/2)
		ret, _, err := procEvtRender.Call(
			0,                                       // Context (NULL for XML rendering)
			uintptr(eventHandle),                    // Event handle
			EvtRenderEventXml,                       // Flags
			uintptr(bufferUsed),                     // BufferSize
			uintptr(unsafe.Pointer(&buffer[0])),     // Buffer
			uintptr(unsafe.Pointer(&bufferUsed)),    // BufferUsed (output)
			uintptr(unsafe.Pointer(&propertyCount)), // PropertyCount (output)
		)

		if ret != 0 {
			xmlString := windows.UTF16ToString(buffer)
			return xmlString, nil
		}
		return "", fmt.Errorf("EvtRender failed: %v", err)
	}

	return "", fmt.Errorf("bufferUsed is 0, cannot render event")
}

// Note: Windows Event Log API functions and constants are shared with sysmon_consumer.go
// They are declared there to avoid duplication
