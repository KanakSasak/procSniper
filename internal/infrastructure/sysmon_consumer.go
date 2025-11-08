//go:build windows

package infrastructure

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"procSniper/internal/domain"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sysmon Event IDs
const (
	EventIDProcessCreate  = 1  // Process creation
	EventIDFileCreateTime = 2  // File creation time changed (detects modifications/overwrites)
	EventIDProcessAccess  = 10 // Process accessed
	EventIDFileCreate     = 11 // File created
	EventIDFileDelete     = 23 // File deleted
)

// Windows Event Log API
var (
	modWevtapi                 = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe           = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext                = modWevtapi.NewProc("EvtNext")
	procEvtRender              = modWevtapi.NewProc("EvtRender")
	procEvtCreateRenderContext = modWevtapi.NewProc("EvtCreateRenderContext")
	procEvtClose               = modWevtapi.NewProc("EvtClose")
)

// Event subscription flags
const (
	EvtSubscribeToFutureEvents = 1
	EvtRenderEventXml          = 1
)

// SysmonEvent represents a parsed Sysmon event
type SysmonEventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer  string `xml:"Computer"`
		Execution struct {
			ProcessID int `xml:"ProcessID,attr"`
		} `xml:"Execution"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// EventProcessor is an interface for processing Sysmon events
// This allows the SysmonConsumer to work with any detection service implementation
type EventProcessor interface {
	ProcessFileCreate(ctx context.Context, event *domain.SysmonEvent)
	ProcessFileModified(ctx context.Context, event *domain.SysmonEvent)
	ProcessFileDelete(ctx context.Context, event *domain.SysmonEvent)
	ProcessProcessCreate(ctx context.Context, event *domain.SysmonEvent)
	ProcessLSASSAccess(ctx context.Context, event *domain.SysmonEvent)
	ProcessBrowserAccess(ctx context.Context, event *domain.SysmonEvent)
}

// SysmonConsumer consumes Sysmon events in real-time
type SysmonConsumer struct {
	eventProcessor EventProcessor
	workerPoolSize int
	eventChannel   chan []byte
	wg             sync.WaitGroup
	mu             sync.RWMutex
	running        bool
}

// NewSysmonConsumer creates a new Sysmon event consumer
func NewSysmonConsumer(eventProcessor EventProcessor, workerPoolSize int) *SysmonConsumer {
	return &SysmonConsumer{
		eventProcessor: eventProcessor,
		workerPoolSize: workerPoolSize,
		eventChannel:   make(chan []byte, 1000), // Buffer 1000 events
		running:        false,
	}
}

// Start begins consuming Sysmon events
func (sc *SysmonConsumer) Start(ctx context.Context) error {
	sc.mu.Lock()
	if sc.running {
		sc.mu.Unlock()
		return fmt.Errorf("Sysmon consumer already running")
	}
	sc.running = true
	sc.mu.Unlock()

	log.Println("[*] Starting Sysmon event consumer...")
	log.Printf("[*] Worker pool size: %d\n", sc.workerPoolSize)

	// Start worker pool
	for i := 0; i < sc.workerPoolSize; i++ {
		sc.wg.Add(1)
		go sc.eventWorker(ctx, i)
	}

	// Start event subscription
	sc.wg.Add(1)
	go sc.subscribeToSysmonEvents(ctx)

	log.Println("[+] Sysmon event consumer started successfully")
	return nil
}

// Stop gracefully shuts down the consumer
func (sc *SysmonConsumer) Stop() {
	sc.mu.Lock()
	if !sc.running {
		sc.mu.Unlock()
		return
	}
	sc.running = false
	sc.mu.Unlock()

	log.Println("[*] Stopping Sysmon event consumer...")
	close(sc.eventChannel)
	sc.wg.Wait()
	log.Println("[+] Sysmon event consumer stopped")
}

// subscribeToSysmonEvents subscribes to Sysmon event log
func (sc *SysmonConsumer) subscribeToSysmonEvents(ctx context.Context) {
	defer sc.wg.Done()

	// XPath query to filter relevant Sysmon events
	// Event IDs: 1 (ProcessCreate), 2 (FileCreateTime/modify), 10 (ProcessAccess), 11 (FileCreate), 23 (FileDelete)
	query := "*[System[(EventID=1 or EventID=2 or EventID=10 or EventID=11 or EventID=23)]]"
	channelPath := "Microsoft-Windows-Sysmon/Operational"

	// Check if Sysmon channel exists
	log.Printf("[*] Checking Sysmon channel: %s\n", channelPath)

	queryPtr, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		log.Printf("[!] Failed to convert query to UTF16: %v\n", err)
		return
	}

	channelPtr, err := syscall.UTF16PtrFromString(channelPath)
	if err != nil {
		log.Printf("[!] Failed to convert channel path to UTF16: %v\n", err)
		return
	}

	// Create an event handle for signaling
	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		log.Printf("[!] Failed to create signal event: %v\n", err)
		return
	}
	defer windows.CloseHandle(signalEvent)

	// Subscribe to events
	ret, _, err := procEvtSubscribe.Call(
		0,                                   // Session
		uintptr(signalEvent),                // SignalEvent (required for polling)
		uintptr(unsafe.Pointer(channelPtr)), // ChannelPath
		uintptr(unsafe.Pointer(queryPtr)),   // Query
		0,                                   // Bookmark
		0,                                   // Context
		0,                                   // Callback (NULL for pull subscription)
		EvtSubscribeToFutureEvents,          // Flags
	)

	if ret == 0 {
		log.Printf("[!] EvtSubscribe failed: %v\n", err)
		log.Printf("[!] This usually means:\n")
		log.Printf("    1. Sysmon is not installed (run: sysmon64.exe -accepteula -i)\n")
		log.Printf("    2. Sysmon is not running (run: Get-Service Sysmon64)\n")
		log.Printf("    3. The event log channel doesn't exist\n")
		log.Printf("    4. Insufficient privileges (run as Administrator)\n")
		log.Printf("[*] Attempting to continue without Sysmon events...\n")
		return
	}

	subscriptionHandle := windows.Handle(ret)
	defer procEvtClose.Call(uintptr(subscriptionHandle))

	log.Printf("[+] Subscribed to Sysmon events: %s\n", channelPath)

	// Poll for events
	sc.pollEvents(ctx, subscriptionHandle)
}

// pollEvents continuously polls for new events
func (sc *SysmonConsumer) pollEvents(ctx context.Context, subscription windows.Handle) {
	log.Println("[*] Event polling loop started - waiting for Sysmon events...")
	pollCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] Sysmon event polling stopped (context cancelled)")
			return
		default:
			// Create fresh events array and pointer for each iteration
			events := make([]windows.Handle, 10)
			var returned uint32
			timeout := uint32(1000) // 1 second timeout

			// Get next batch of events
			ret, _, err := procEvtNext.Call(
				uintptr(subscription),
				uintptr(len(events)),
				uintptr(unsafe.Pointer(&events[0])), // Fresh pointer each time
				uintptr(timeout),
				0,
				uintptr(unsafe.Pointer(&returned)),
			)

			pollCount++

			// Debug logging every 10 seconds (100 polls at 100ms each)
			if pollCount%100 == 0 {
				log.Printf("[DEBUG] Polling cycle %d: EvtNext ret=%d, returned=%d, err=%v\n",
					pollCount, ret, returned, err)
			}

			if ret == 0 || returned == 0 {
				// No events or timeout
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Events received!
			log.Printf("[+] Received %d new Sysmon events\n", returned)

			// Process each event
			for i := uint32(0); i < returned; i++ {
				eventHandle := events[i]
				log.Printf("[DEBUG] Event %d/%d: handle=%v\n", i+1, returned, eventHandle)

				if eventHandle == 0 {
					log.Printf("[!] Event %d/%d has INVALID handle (0), skipping\n", i+1, returned)
					continue
				}

				// Render event as XML
				eventXML := sc.renderEventAsXML(eventHandle)
				log.Printf("[DEBUG] Event %d/%d: rendered XML size=%d bytes\n", i+1, returned, len(eventXML))

				procEvtClose.Call(uintptr(eventHandle))

				if len(eventXML) > 0 {
					select {
					case sc.eventChannel <- eventXML:
						// Event sent to worker pool
						log.Printf("[DEBUG] Event %d/%d sent to worker pool (queue: %d/%d)\n",
							i+1, returned, len(sc.eventChannel), cap(sc.eventChannel))
					case <-ctx.Done():
						return
					default:
						// Channel full, drop event
						log.Println("[!] Event channel full, dropping event")
					}
				} else {
					log.Printf("[!] Event %d/%d: renderEventAsXML returned EMPTY, skipping\n", i+1, returned)
				}
			}
		}
	}
}

// renderEventAsXML renders an event handle as XML
func (sc *SysmonConsumer) renderEventAsXML(eventHandle windows.Handle) []byte {
	// For XML rendering, pass NULL context (0)
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

	log.Printf("[DEBUG] EvtRender (size check): ret=%d, bufferUsed=%d, err=%v\n", ret1, bufferUsed, err1)

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
			log.Printf("[DEBUG] EvtRender SUCCESS: XML length=%d chars\n", len(xmlString))
			return []byte(xmlString)
		} else {
			log.Printf("[!] EvtRender (actual) failed: ret=%d, err=%v\n", ret, err)
		}
	} else {
		log.Printf("[!] bufferUsed is 0, cannot render event\n")
	}

	return nil
}

// eventWorker processes events from the channel
func (sc *SysmonConsumer) eventWorker(ctx context.Context, workerID int) {
	defer sc.wg.Done()

	log.Printf("[+] Event worker %d started\n", workerID)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[*] Event worker %d stopped (context cancelled)\n", workerID)
			return
		case eventXML, ok := <-sc.eventChannel:
			if !ok {
				log.Printf("[*] Event worker %d stopped (channel closed)\n", workerID)
				return
			}

			sc.processEvent(ctx, eventXML)
		}
	}
}

// processEvent parses and processes a single event
func (sc *SysmonConsumer) processEvent(ctx context.Context, eventXML []byte) {
	var sysmonEvent SysmonEventXML
	if err := xml.Unmarshal(eventXML, &sysmonEvent); err != nil {
		log.Printf("[!] Failed to parse Sysmon event XML: %v\n", err)
		return
	}

	log.Printf("[DEBUG] Processing Event ID %d: %s (PID: %d)\n",
		sysmonEvent.System.EventID,
		sysmonEvent.System.Computer,
		sysmonEvent.System.Execution.ProcessID)

	// Convert to domain event
	domainEvent := sc.xmlToDomainEvent(&sysmonEvent)
	if domainEvent == nil {
		return
	}

	// Route to appropriate handler based on Event ID
	switch sysmonEvent.System.EventID {
	case EventIDProcessCreate:
		log.Printf("[EVENT] Process created: %s (PID: %d)\n", domainEvent.Image, domainEvent.ProcessID)
		sc.eventProcessor.ProcessProcessCreate(ctx, domainEvent)
	case EventIDFileCreateTime:
		// Event ID 2: File modification/overwrite (CRITICAL for in-place encryption detection)
		log.Printf("[EVENT] File modified: %s (by PID: %d)\n", domainEvent.TargetFile, domainEvent.ProcessID)
		// Use dedicated handler for file modifications - detects entropy increases
		sc.eventProcessor.ProcessFileModified(ctx, domainEvent)
	case EventIDProcessAccess:
		log.Printf("[EVENT] Process access: %s -> %s\n", domainEvent.Image, domainEvent.TargetImage)
		sc.eventProcessor.ProcessLSASSAccess(ctx, domainEvent)
	case EventIDFileCreate:
		log.Printf("[EVENT] File created: %s (by PID: %d)\n", domainEvent.TargetFile, domainEvent.ProcessID)
		sc.eventProcessor.ProcessFileCreate(ctx, domainEvent)
	case EventIDFileDelete:
		log.Printf("[EVENT] File deleted: %s (by PID: %d)\n", domainEvent.TargetFile, domainEvent.ProcessID)
		sc.eventProcessor.ProcessFileDelete(ctx, domainEvent)
	default:
		log.Printf("[*] Unhandled event ID: %d\n", sysmonEvent.System.EventID)
	}
}

// xmlToDomainEvent converts XML event to domain event
func (sc *SysmonConsumer) xmlToDomainEvent(xmlEvent *SysmonEventXML) *domain.SysmonEvent {
	event := &domain.SysmonEvent{
		EventID:   xmlEvent.System.EventID,
		Timestamp: time.Now(), // Parse xmlEvent.System.TimeCreated if needed
		Computer:  xmlEvent.System.Computer,
	}

	// Extract event data fields
	dataMap := make(map[string]string)
	for _, data := range xmlEvent.EventData.Data {
		dataMap[data.Name] = data.Value
	}

	// Map common fields (only those that exist in domain.SysmonEvent)
	event.ProcessGuid = dataMap["ProcessGuid"]
	event.Image = dataMap["Image"]
	event.CommandLine = dataMap["CommandLine"]
	event.TargetFile = dataMap["TargetFilename"]
	event.TargetImage = dataMap["TargetImage"]
	event.GrantedAccess = dataMap["GrantedAccess"]

	// Event ID 10 uses "SourceProcessId" not "ProcessId"
	if xmlEvent.System.EventID == 10 {
		if sourcePid := dataMap["SourceProcessId"]; sourcePid != "" {
			fmt.Sscanf(sourcePid, "%d", &event.ProcessID)
		}
	} else {
		if pid := dataMap["ProcessId"]; pid != "" {
			fmt.Sscanf(pid, "%d", &event.ProcessID)
		}
	}

	return event
}

// GetStats returns consumer statistics
func (sc *SysmonConsumer) GetStats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	return map[string]interface{}{
		"running":          sc.running,
		"worker_pool_size": sc.workerPoolSize,
		"channel_length":   len(sc.eventChannel),
		"channel_capacity": cap(sc.eventChannel),
	}
}
