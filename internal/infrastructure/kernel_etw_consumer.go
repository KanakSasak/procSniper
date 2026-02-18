//go:build windows

package infrastructure

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bi-zone/etw"
	"golang.org/x/sys/windows"

	"procSniper/internal/domain"
)

// ETW Provider GUIDs
var (
	// Microsoft-Windows-Kernel-Process
	KernelProcessGUID = windows.GUID{
		Data1: 0x22FB2CD6,
		Data2: 0x0E7B,
		Data3: 0x422B,
		Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16},
	}
	// Microsoft-Windows-Kernel-File
	KernelFileGUID = windows.GUID{
		Data1: 0xEDD08927,
		Data2: 0x9CC4,
		Data3: 0x4E65,
		Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89},
	}
	// Microsoft-Windows-Kernel-Audit-API-Calls
	KernelAuditAPIGUID = windows.GUID{
		Data1: 0xE02A841C,
		Data2: 0x75A3,
		Data3: 0x4FA7,
		Data4: [8]byte{0xAF, 0xC8, 0xAE, 0x09, 0xCF, 0x9B, 0x7F, 0x23},
	}
)

// Kernel ETW Event IDs
const (
	// Microsoft-Windows-Kernel-Process
	ETWEventProcessStart = 1
	ETWEventProcessStop  = 2

	// Microsoft-Windows-Kernel-File
	ETWEventFileCreate     = 12
	ETWEventFileCleanup    = 13
	ETWEventFileClose      = 14
	ETWEventFileRead       = 15
	ETWEventFileWrite      = 16
	ETWEventFileSetInfo    = 17
	ETWEventFileDelete     = 18
	ETWEventFileRename     = 19
	ETWEventFileDirEnum    = 20
	ETWEventFileFlush      = 21
	ETWEventFileQueryInfo  = 22
	ETWEventFileFSCTL      = 23
	ETWEventFileDleteePath = 26
	ETWEventFileRenamePath = 27
	ETWEventFileCreateNew  = 30

	// Microsoft-Windows-Kernel-Audit-API-Calls
	ETWEventOpenProcess = 5
)

// Kernel-File keyword filters
const (
	KERNEL_FILE_KEYWORD_FILEIO      = 0x10
	KERNEL_FILE_KEYWORD_CREATE      = 0x80000
	KERNEL_FILE_KEYWORD_DELETE_PATH = 0x8000000
	KERNEL_FILE_KEYWORD_RENAME_PATH = 0x10000000

	deadPIDTTL    = 120 * time.Second
	skewTolerance = 2 * time.Second
)

// writeDebounceKey is used to debounce write events per (PID, FileKey)
type writeDebounceKey struct {
	PID     uint32
	FileKey uint64
}

// FileObjectEntry stores the file path and opener's PID/GUID for cross-process correlation.
type FileObjectEntry struct {
	Path       string
	OpenerPID  uint32
	OpenerGUID string
}

// DeadProcessRecord stores recently terminated process context for post-kill suppression.
type DeadProcessRecord struct {
	PID         uint32
	ProcessGuid string
	Image       string
	DeadAt      time.Time
	Source      string
	RetireAt    time.Time
}

// KernelETWConsumer consumes events from Windows kernel ETW providers.
type KernelETWConsumer struct {
	eventProcessor domain.EventProcessor
	workerPoolSize int
	eventChannel   chan *domain.MonitorEvent
	wg             sync.WaitGroup
	mu             sync.RWMutex
	running        bool

	// ETW sessions (one per provider)
	processSession *etw.Session
	fileSession    *etw.Session
	auditSession   *etw.Session

	// PID -> ProcessGuid cache (populated by ProcessStart events)
	pidGuidCache map[uint32]string
	pidGuidMux   sync.RWMutex

	// FileObject -> FileObjectEntry cache (populated by Create events)
	fileObjectCache map[uint64]FileObjectEntry
	fileObjectMux   sync.RWMutex

	// Write event debouncer
	writeDebounce    map[writeDebounceKey]time.Time
	writeDebounceMux sync.Mutex

	// Recently dead process tracking for post-kill ETW suppression.
	deadProcesses map[uint32]DeadProcessRecord
	deadMux       sync.RWMutex

	// LSASS PID (resolved at startup, refreshed periodically)
	lsassPID uint32
	lsassMux sync.RWMutex

	// Process image path cache
	imageCache map[uint32]string
	imageMux   sync.RWMutex

	// Stats
	eventsReceived          uint64
	eventsDropped           uint64
	eventsSuppressedDeadPID uint64

	// Context cancellation
	cancelFunc context.CancelFunc
}

// NewKernelETWConsumer creates a new kernel ETW event consumer.
func NewKernelETWConsumer(eventProcessor domain.EventProcessor, workerPoolSize int) *KernelETWConsumer {
	return &KernelETWConsumer{
		eventProcessor:  eventProcessor,
		workerPoolSize:  workerPoolSize,
		eventChannel:    make(chan *domain.MonitorEvent, 1000),
		pidGuidCache:    make(map[uint32]string),
		fileObjectCache: make(map[uint64]FileObjectEntry),
		writeDebounce:   make(map[writeDebounceKey]time.Time),
		imageCache:      make(map[uint32]string),
		deadProcesses:   make(map[uint32]DeadProcessRecord),
	}
}

// Start begins consuming kernel ETW events.
func (kc *KernelETWConsumer) Start(ctx context.Context) error {
	kc.mu.Lock()
	if kc.running {
		kc.mu.Unlock()
		return fmt.Errorf("ETW consumer already running")
	}
	kc.running = true
	kc.mu.Unlock()

	log.Println("[*] Starting Kernel ETW event consumer...")
	log.Printf("[*] Worker pool size: %d\n", kc.workerPoolSize)

	// Resolve LSASS PID
	lsassPID, err := resolveLSASSPid()
	if err != nil {
		log.Printf("[!] WARNING: Could not resolve LSASS PID: %v\n", err)
		log.Println("[!] LSASS access detection will be limited")
	} else {
		kc.lsassPID = lsassPID
		log.Printf("[+] LSASS PID resolved: %d\n", lsassPID)
	}

	// Create ETW sessions
	if err := kc.createSessions(); err != nil {
		kc.running = false
		return fmt.Errorf("failed to create ETW sessions: %w", err)
	}

	// Create cancellable context
	sessionCtx, cancel := context.WithCancel(ctx)
	kc.cancelFunc = cancel

	// Start worker pool
	for i := 0; i < kc.workerPoolSize; i++ {
		kc.wg.Add(1)
		go kc.eventWorker(sessionCtx, i)
	}

	// Start ETW session processing goroutines
	kc.startSessionProcessing(sessionCtx)

	// Start background cache cleanup
	kc.wg.Add(1)
	go kc.cleanupCaches(sessionCtx)

	// Start periodic LSASS PID refresh
	kc.wg.Add(1)
	go kc.refreshLSASSPid(sessionCtx)

	log.Println("[+] Kernel ETW event consumer started successfully")
	log.Println("[+] Providers:")
	log.Println("    - Microsoft-Windows-Kernel-Process (process creation)")
	log.Println("    - Microsoft-Windows-Kernel-File (file create/write/delete)")
	log.Println("    - Microsoft-Windows-Kernel-Audit-API-Calls (LSASS access)")
	return nil
}

// Stop gracefully shuts down the consumer.
func (kc *KernelETWConsumer) Stop() {
	kc.mu.Lock()
	if !kc.running {
		kc.mu.Unlock()
		return
	}
	kc.running = false
	kc.mu.Unlock()

	log.Println("[*] Stopping Kernel ETW event consumer...")

	// Cancel context
	if kc.cancelFunc != nil {
		kc.cancelFunc()
	}

	// Close ETW sessions (unblocks Process() calls)
	if kc.processSession != nil {
		kc.processSession.Close()
	}
	if kc.fileSession != nil {
		kc.fileSession.Close()
	}
	if kc.auditSession != nil {
		kc.auditSession.Close()
	}

	close(kc.eventChannel)
	kc.wg.Wait()
	log.Println("[+] Kernel ETW event consumer stopped")
}

// GetStats returns consumer statistics.
func (kc *KernelETWConsumer) GetStats() map[string]interface{} {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	return map[string]interface{}{
		"running":                    kc.running,
		"worker_pool_size":           kc.workerPoolSize,
		"channel_length":             len(kc.eventChannel),
		"channel_capacity":           cap(kc.eventChannel),
		"events_received":            atomic.LoadUint64(&kc.eventsReceived),
		"events_dropped":             atomic.LoadUint64(&kc.eventsDropped),
		"events_suppressed_dead_pid": atomic.LoadUint64(&kc.eventsSuppressedDeadPID),
	}
}

// createSessions creates the 3 kernel ETW sessions.
func (kc *KernelETWConsumer) createSessions() error {
	var err error

	// Session 1: Kernel-Process (ProcessStart events)
	kc.processSession, err = kc.createSessionWithRetry(
		KernelProcessGUID,
		"procSniper-KernelProcess",
		etw.WithLevel(etw.TRACE_LEVEL_INFORMATION),
	)
	if err != nil {
		return fmt.Errorf("kernel-process session: %w", err)
	}
	log.Println("[+] ETW session created: Microsoft-Windows-Kernel-Process")

	// Session 2: Kernel-File (Create, Write, Delete events)
	kc.fileSession, err = kc.createSessionWithRetry(
		KernelFileGUID,
		"procSniper-KernelFile",
		etw.WithLevel(etw.TRACE_LEVEL_INFORMATION),
	)
	if err != nil {
		kc.processSession.Close()
		return fmt.Errorf("kernel-file session: %w", err)
	}
	log.Println("[+] ETW session created: Microsoft-Windows-Kernel-File")

	// Session 3: Kernel-Audit-API-Calls (OpenProcess for LSASS detection)
	kc.auditSession, err = kc.createSessionWithRetry(
		KernelAuditAPIGUID,
		"procSniper-KernelAudit",
		etw.WithLevel(etw.TRACE_LEVEL_INFORMATION),
	)
	if err != nil {
		kc.processSession.Close()
		kc.fileSession.Close()
		return fmt.Errorf("kernel-audit session: %w", err)
	}
	log.Println("[+] ETW session created: Microsoft-Windows-Kernel-Audit-API-Calls")

	return nil
}

// createSessionWithRetry creates an ETW session, handling stale session conflicts.
func (kc *KernelETWConsumer) createSessionWithRetry(guid windows.GUID, name string, opts ...etw.Option) (*etw.Session, error) {
	allOpts := append([]etw.Option{etw.WithName(name)}, opts...)
	session, err := etw.NewSession(guid, allOpts...)
	if err != nil {
		// Handle stale session from previous crash
		if existsErr, ok := err.(etw.ExistsError); ok {
			log.Printf("[*] Killing stale ETW session: %s\n", existsErr.SessionName)
			if killErr := etw.KillSession(existsErr.SessionName); killErr != nil {
				return nil, fmt.Errorf("failed to kill stale session %s: %w", existsErr.SessionName, killErr)
			}
			// Retry
			session, err = etw.NewSession(guid, allOpts...)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return session, nil
}

// startSessionProcessing starts goroutines to process events from each ETW session.
func (kc *KernelETWConsumer) startSessionProcessing(ctx context.Context) {
	// Goroutine 1: Kernel-Process events
	kc.wg.Add(1)
	go func() {
		defer kc.wg.Done()
		log.Println("[+] ETW processing started: Kernel-Process")
		if err := kc.processSession.Process(func(e *etw.Event) {
			kc.handleProcessEvent(ctx, e)
		}); err != nil {
			log.Printf("[!] Kernel-Process session processing ended: %v\n", err)
		}
	}()

	// Goroutine 2: Kernel-File events
	kc.wg.Add(1)
	go func() {
		defer kc.wg.Done()
		log.Println("[+] ETW processing started: Kernel-File")
		if err := kc.fileSession.Process(func(e *etw.Event) {
			kc.handleFileEvent(ctx, e)
		}); err != nil {
			log.Printf("[!] Kernel-File session processing ended: %v\n", err)
		}
	}()

	// Goroutine 3: Kernel-Audit events
	kc.wg.Add(1)
	go func() {
		defer kc.wg.Done()
		log.Println("[+] ETW processing started: Kernel-Audit-API-Calls")
		if err := kc.auditSession.Process(func(e *etw.Event) {
			kc.handleAuditEvent(ctx, e)
		}); err != nil {
			log.Printf("[!] Kernel-Audit session processing ended: %v\n", err)
		}
	}()
}

// ============================================================================
// Process Event Handler (replaces Sysmon Event ID 1)
// ============================================================================

func (kc *KernelETWConsumer) handleProcessEvent(ctx context.Context, e *etw.Event) {
	if e.Header.ID != ETWEventProcessStart {
		// Also handle ProcessStop to clean up caches
		if e.Header.ID == ETWEventProcessStop {
			kc.handleProcessStop(e)
		}
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	// The new process PID is in the event data
	newPID := getUint32Prop(props, "ProcessID")
	if newPID == 0 {
		// Fallback: sometimes the field is named differently
		newPID = e.Header.ProcessID
	}

	createTime := e.Header.TimeStamp

	// Generate synthetic ProcessGuid
	processGuid := fmt.Sprintf("ETW-%d-%d", newPID, createTime.UnixNano())

	// PID reuse: clear any dead-process marker before assigning a new identity.
	kc.deadMux.Lock()
	delete(kc.deadProcesses, newPID)
	kc.deadMux.Unlock()

	// Cache the PID -> GUID mapping
	kc.pidGuidMux.Lock()
	kc.pidGuidCache[newPID] = processGuid
	kc.pidGuidMux.Unlock()

	// Resolve full image path
	imagePath := resolveProcessImage(newPID)
	if imagePath == "" {
		imagePath = getStringProp(props, "ImageName")
		if imagePath != "" {
			imagePath = convertDevicePath(imagePath)
		}
	}

	// Cache image path
	kc.imageMux.Lock()
	kc.imageCache[newPID] = imagePath
	kc.imageMux.Unlock()

	// Resolve command line (may fail for short-lived processes)
	commandLine := resolveCommandLine(newPID)
	parentPID := getUint32Prop(props, "ParentProcessID")
	if parentPID == 0 {
		parentPID = getUint32Prop(props, "ParentID")
	}
	// Toolhelp32 fallback when ETW PPID is 0 (common for ransomware child processes)
	if parentPID == 0 && newPID != 0 {
		parentPID = resolveParentPID(newPID)
		if parentPID != 0 {
			log.Printf("[ETW] Resolved PPID via Toolhelp32 fallback: PID=%d -> PPID=%d", newPID, parentPID)
		}
	}

	event := &domain.MonitorEvent{
		EventID:     1,
		Timestamp:   createTime,
		Computer:    getHostname(),
		ProcessGuid: processGuid,
		ProcessID:   int(newPID),
		Image:       imagePath,
		CommandLine: commandLine,
		RawData: map[string]interface{}{
			"parent_process_id": parentPID,
		},
	}

	log.Printf("[EVENT] Process created: %s (PID: %d, PPID: %d)\n", imagePath, newPID, parentPID)
	if commandLine != "" {
		log.Printf("[EVENT] Process command line: %s\n", commandLine)
	}
	kc.enqueueEvent(ctx, event)
}

func (kc *KernelETWConsumer) handleProcessStop(e *etw.Event) {
	props, _ := e.EventProperties()
	pid := getUint32Prop(props, "ProcessID")
	if pid == 0 {
		pid = e.Header.ProcessID
	}

	processGuid := kc.lookupProcessGuid(pid)
	imagePath := kc.lookupProcessImage(pid)
	kc.markProcessDead(pid, processGuid, imagePath, e.Header.TimeStamp, "process_stop")
}

// ============================================================================
// File Event Handler (replaces Sysmon Event IDs 2, 11, 23)
// ============================================================================

func (kc *KernelETWConsumer) handleFileEvent(ctx context.Context, e *etw.Event) {
	switch e.Header.ID {
	case ETWEventFileCreate:
		// Event ID 12: All file opens - cache FileObject→FilePath and filter for actual creates
		kc.handleFileOpen(ctx, e)
	case ETWEventFileCreateNew:
		// Event ID 30: New file creation only (direct replacement for Sysmon Event ID 11)
		kc.handleFileCreateNew(ctx, e)
	case ETWEventFileWrite:
		// Event ID 16: File write (replacement for Sysmon Event ID 2 - in-place modification)
		kc.handleFileWrite(ctx, e)
	case ETWEventFileSetInfo:
		// Event ID 17: File set information (includes FileRenameInformation)
		kc.handleFileSetInfo(ctx, e)
	case ETWEventFileDelete:
		// Event ID 18: File delete (provider variant on some systems)
		kc.handleFileDelete(ctx, e)
	case ETWEventFileRename:
		// Event ID 19: File rename (provider variant on some systems)
		kc.handleFileRename(ctx, e)
	case ETWEventFileDleteePath:
		// Event ID 26: File delete (replacement for Sysmon Event ID 23)
		kc.handleFileDelete(ctx, e)
	case ETWEventFileRenamePath:
		// Event ID 27: File rename - also track as modification
		kc.handleFileRename(ctx, e)
	case ETWEventFileClose:
		// Event ID 14: Clean up FileObject cache on close
		kc.handleFileClose(e)
	}
}

// handleFileOpen processes Event ID 12 (Create/Open).
// This fires for ALL file opens. We cache FileObject→FilePath for write correlation
// and only emit a FileCreate event for actual file creation dispositions.
func (kc *KernelETWConsumer) handleFileOpen(ctx context.Context, e *etw.Event) {
	if kc.shouldSuppressFileEvent(e.Header.ProcessID, e.Header.TimeStamp) {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	fileName := getStringProp(props, "FileName")
	if fileName == "" {
		fileName = getStringProp(props, "OpenPath")
	}
	if fileName == "" {
		return
	}

	filePath := convertDevicePath(fileName)

	// Always cache FileObject → FileObjectEntry for write/delete/rename correlation
	fileObject := getUint64Prop(props, "FileObject")
	pid := e.Header.ProcessID
	entry := FileObjectEntry{
		Path:       filePath,
		OpenerPID:  pid,
		OpenerGUID: kc.lookupProcessGuid(pid),
	}
	if fileObject != 0 {
		kc.fileObjectMux.Lock()
		kc.fileObjectCache[fileObject] = entry
		kc.fileObjectMux.Unlock()
	}

	// Also cache under FileKey if available
	fileKey := getUint64Prop(props, "FileKey")
	if fileKey != 0 {
		kc.fileObjectMux.Lock()
		kc.fileObjectCache[fileKey] = entry
		kc.fileObjectMux.Unlock()
	}

	// Check create disposition using explicit field first, then CreateOptions fallback.
	// This is the Sysmon Event 11-equivalent gate:
	// - Win32 CreateDisposition: CREATE_NEW(1), CREATE_ALWAYS(2), OPEN_ALWAYS(4), TRUNCATE_EXISTING(5)
	// - NT CreateDisposition (embedded in CreateOptions high byte): SUPERSEDE(0), CREATE(2), OPEN_IF(3), OVERWRITE(4), OVERWRITE_IF(5)
	if shouldEmitFileCreate(props) {
		// This is an actual create/overwrite-style operation, emit EventID 11 equivalent
		kc.emitFileCreate(ctx, e, filePath)
	}
}

// handleFileCreateNew processes Event ID 30 (CreateNewFile).
// This fires only when a new file is created — direct replacement for Sysmon Event ID 11.
func (kc *KernelETWConsumer) handleFileCreateNew(ctx context.Context, e *etw.Event) {
	if kc.shouldSuppressFileEvent(e.Header.ProcessID, e.Header.TimeStamp) {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	fileName := getStringProp(props, "FileName")
	if fileName == "" {
		fileName = getStringProp(props, "OpenPath")
	}
	if fileName == "" {
		return
	}

	filePath := convertDevicePath(fileName)

	// Cache FileObject → FileObjectEntry
	fileObject := getUint64Prop(props, "FileObject")
	if fileObject != 0 {
		pid := e.Header.ProcessID
		kc.fileObjectMux.Lock()
		kc.fileObjectCache[fileObject] = FileObjectEntry{
			Path:       filePath,
			OpenerPID:  pid,
			OpenerGUID: kc.lookupProcessGuid(pid),
		}
		kc.fileObjectMux.Unlock()
	}

	kc.emitFileCreate(ctx, e, filePath)
}

func (kc *KernelETWConsumer) emitFileCreate(ctx context.Context, e *etw.Event, filePath string) {
	pid := e.Header.ProcessID
	if kc.shouldSuppressFileEvent(pid, e.Header.TimeStamp) {
		return
	}

	processGuid := kc.lookupProcessGuid(pid)
	imagePath := kc.lookupProcessImage(pid)

	event := &domain.MonitorEvent{
		EventID:     11, // Map to Sysmon-compatible Event ID for detection service
		Timestamp:   e.Header.TimeStamp,
		Computer:    getHostname(),
		ProcessGuid: processGuid,
		ProcessID:   int(pid),
		Image:       imagePath,
		TargetFile:  filePath,
	}

	log.Printf("[EVENT] File created: %s (by PID: %d)\n", filePath, pid)
	kc.enqueueEvent(ctx, event)
}

// handleFileWrite processes Event ID 16 (Write).
// Replaces Sysmon Event ID 2 (FileCreateTime change / in-place modification).
func (kc *KernelETWConsumer) handleFileWrite(ctx context.Context, e *etw.Event) {
	if kc.shouldSuppressFileEvent(e.Header.ProcessID, e.Header.TimeStamp) {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	// Write events carry FileObject/FileKey, not FileName
	fileKey := getUint64Prop(props, "FileKey")
	fileObject := getUint64Prop(props, "FileObject")

	filePath := kc.lookupFilePath(fileKey, fileObject)
	if filePath == "" {
		return
	}

	pid := e.Header.ProcessID

	// Debounce: only emit one write event per (PID, FileKey) per second
	debounceKey := writeDebounceKey{PID: pid, FileKey: fileKey}
	kc.writeDebounceMux.Lock()
	if lastEmit, ok := kc.writeDebounce[debounceKey]; ok {
		if time.Since(lastEmit) < time.Second {
			kc.writeDebounceMux.Unlock()
			return
		}
	}
	kc.writeDebounce[debounceKey] = time.Now()
	kc.writeDebounceMux.Unlock()

	processGuid := kc.lookupProcessGuid(pid)
	imagePath := kc.lookupProcessImage(pid)

	event := &domain.MonitorEvent{
		EventID:     2, // Map to Sysmon Event ID 2 for detection service compatibility
		Timestamp:   e.Header.TimeStamp,
		Computer:    getHostname(),
		ProcessGuid: processGuid,
		ProcessID:   int(pid),
		Image:       imagePath,
		TargetFile:  filePath,
	}

	log.Printf("[EVENT] File modified: %s (by PID: %d)\n", filePath, pid)
	kc.enqueueEvent(ctx, event)
}

// handleFileSetInfo processes Event ID 17 (SetInfo).
// We use InfoClass=10/65 as rename indicators and map them to EventID 2-style modification telemetry.
func (kc *KernelETWConsumer) handleFileSetInfo(ctx context.Context, e *etw.Event) {
	if kc.shouldSuppressFileEvent(e.Header.ProcessID, e.Header.TimeStamp) {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	infoClass, ok := extractInfoClass(props)
	if !ok {
		return
	}

	// 10 = FileRenameInformation, 65 = FileRenameInformationEx
	if infoClass != 10 && infoClass != 65 {
		return
	}

	filePath := getStringProp(props, "FilePath")
	if filePath == "" {
		filePath = getStringProp(props, "FileName")
	}
	if filePath == "" {
		filePath = getStringProp(props, "OpenPath")
	}
	// Try to resolve file path and opener info from cache
	fileKey := getUint64Prop(props, "FileKey")
	fileObject := getUint64Prop(props, "FileObject")
	var openerPID uint32
	var openerGUID string

	if filePath == "" {
		if entry, found := kc.lookupFileObjectEntry(fileKey, fileObject); found {
			filePath = entry.Path
			openerPID = entry.OpenerPID
			openerGUID = entry.OpenerGUID
		}
	} else {
		// Path came from props; still look up opener info
		if entry, found := kc.lookupFileObjectEntry(fileKey, fileObject); found {
			openerPID = entry.OpenerPID
			openerGUID = entry.OpenerGUID
		}
	}
	if filePath == "" {
		return
	}

	filePath = convertDevicePath(filePath)
	pid := e.Header.ProcessID
	processGuid := kc.lookupProcessGuid(pid)
	imagePath := kc.lookupProcessImage(pid)

	rawData := map[string]interface{}{
		"set_info_class": infoClass,
		"set_info_type":  "rename",
	}
	if openerPID != 0 {
		rawData["opener_pid"] = openerPID
		rawData["opener_guid"] = openerGUID
	}

	event := &domain.MonitorEvent{
		EventID:     2, // Sysmon-compatible "file modified/renamed"
		Timestamp:   e.Header.TimeStamp,
		Computer:    getHostname(),
		ProcessGuid: processGuid,
		ProcessID:   int(pid),
		Image:       imagePath,
		TargetFile:  filePath,
		RawData:     rawData,
	}

	log.Printf("[EVENT] File rename (SetInfo): %s (by PID: %d, InfoClass: %d, OpenerPID: %d)\n", filePath, pid, infoClass, openerPID)
	kc.enqueueEvent(ctx, event)
}

// handleFileDelete processes Event ID 26 (DeletePath).
// Replaces Sysmon Event ID 23.
func (kc *KernelETWConsumer) handleFileDelete(ctx context.Context, e *etw.Event) {
	if kc.shouldSuppressFileEvent(e.Header.ProcessID, e.Header.TimeStamp) {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	filePath := getStringProp(props, "FilePath")
	if filePath == "" {
		filePath = getStringProp(props, "FileName")
	}
	if filePath == "" {
		return
	}

	filePath = convertDevicePath(filePath)
	pid := e.Header.ProcessID
	processGuid := kc.lookupProcessGuid(pid)
	imagePath := kc.lookupProcessImage(pid)

	event := &domain.MonitorEvent{
		EventID:     23, // Map to Sysmon Event ID 23
		Timestamp:   e.Header.TimeStamp,
		Computer:    getHostname(),
		ProcessGuid: processGuid,
		ProcessID:   int(pid),
		Image:       imagePath,
		TargetFile:  filePath,
	}

	log.Printf("[EVENT] File deleted: %s (by PID: %d)\n", filePath, pid)
	kc.enqueueEvent(ctx, event)
}

// handleFileRename processes Event ID 27 (RenamePath).
// Tracked as a modification event for detection purposes.
func (kc *KernelETWConsumer) handleFileRename(ctx context.Context, e *etw.Event) {
	if kc.shouldSuppressFileEvent(e.Header.ProcessID, e.Header.TimeStamp) {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	filePath := getStringProp(props, "FilePath")
	if filePath == "" {
		filePath = getStringProp(props, "FileName")
	}
	if filePath == "" {
		return
	}

	filePath = convertDevicePath(filePath)
	pid := e.Header.ProcessID
	processGuid := kc.lookupProcessGuid(pid)
	imagePath := kc.lookupProcessImage(pid)

	rawData := map[string]interface{}{
		"set_info_type": "rename",
		"event_source":  "rename_path",
	}

	// Look up opener PID/GUID from cache for cross-process correlation
	fileKey := getUint64Prop(props, "FileKey")
	fileObject := getUint64Prop(props, "FileObject")
	if entry, found := kc.lookupFileObjectEntry(fileKey, fileObject); found {
		if entry.OpenerPID != 0 {
			rawData["opener_pid"] = entry.OpenerPID
			rawData["opener_guid"] = entry.OpenerGUID
		}
	}

	event := &domain.MonitorEvent{
		EventID:     2, // Treat rename as modification (like Sysmon Event ID 2)
		Timestamp:   e.Header.TimeStamp,
		Computer:    getHostname(),
		ProcessGuid: processGuid,
		ProcessID:   int(pid),
		Image:       imagePath,
		TargetFile:  filePath,
		RawData:     rawData,
	}

	log.Printf("[EVENT] File renamed: %s (by PID: %d)\n", filePath, pid)
	kc.enqueueEvent(ctx, event)
}

// handleFileClose cleans up the FileObject cache when a file handle is closed.
func (kc *KernelETWConsumer) handleFileClose(e *etw.Event) {
	props, _ := e.EventProperties()
	fileObject := getUint64Prop(props, "FileObject")
	if fileObject != 0 {
		kc.fileObjectMux.Lock()
		delete(kc.fileObjectCache, fileObject)
		kc.fileObjectMux.Unlock()
	}
}

// ============================================================================
// Audit API Event Handler (replaces Sysmon Event ID 10)
// ============================================================================

func (kc *KernelETWConsumer) handleAuditEvent(ctx context.Context, e *etw.Event) {
	if e.Header.ID != ETWEventOpenProcess {
		return
	}

	props, err := e.EventProperties()
	if err != nil {
		return
	}

	targetPID := getUint32Prop(props, "TargetProcessId")
	desiredAccess := getUint32Prop(props, "DesiredAccess")

	// Filter: only care about LSASS access
	kc.lsassMux.RLock()
	lsassPID := kc.lsassPID
	kc.lsassMux.RUnlock()

	if lsassPID == 0 || targetPID != lsassPID {
		return
	}

	// Check for suspicious access masks
	// PROCESS_VM_READ = 0x0010
	// PROCESS_VM_WRITE = 0x0020
	// PROCESS_VM_OPERATION = 0x0008
	// PROCESS_ALL_ACCESS = 0x1FFFFF
	const (
		PROCESS_VM_READ  = 0x0010
		PROCESS_VM_WRITE = 0x0020
		PROCESS_VM_OP    = 0x0008
	)
	suspiciousAccess := (desiredAccess & PROCESS_VM_READ) != 0

	if !suspiciousAccess {
		return
	}

	sourcePID := e.Header.ProcessID
	processGuid := kc.lookupProcessGuid(sourcePID)
	sourceImage := kc.lookupProcessImage(sourcePID)

	// Skip if the source is a known system process
	if sourceImage != "" {
		lowerImage := strings.ToLower(sourceImage)
		if strings.Contains(lowerImage, "csrss.exe") ||
			strings.Contains(lowerImage, "svchost.exe") ||
			strings.Contains(lowerImage, "services.exe") ||
			strings.Contains(lowerImage, "wininit.exe") ||
			strings.Contains(lowerImage, "smss.exe") ||
			strings.Contains(lowerImage, "lsass.exe") {
			return
		}
	}

	// Resolve parent PID for ML feature propagation
	parentPID := resolveParentPID(sourcePID)

	event := &domain.MonitorEvent{
		EventID:       10, // Map to Sysmon Event ID 10
		Timestamp:     e.Header.TimeStamp,
		Computer:      getHostname(),
		ProcessGuid:   processGuid,
		ProcessID:     int(sourcePID),
		Image:         sourceImage,
		TargetImage:   `C:\Windows\System32\lsass.exe`,
		GrantedAccess: fmt.Sprintf("0x%X", desiredAccess),
		RawData: map[string]interface{}{
			"parent_process_id": parentPID,
		},
	}

	log.Printf("[EVENT] Process access: %s -> lsass.exe (Access: 0x%X)\n", sourceImage, desiredAccess)
	kc.enqueueEvent(ctx, event)
}

// ============================================================================
// Worker Pool and Event Routing
// ============================================================================

func (kc *KernelETWConsumer) enqueueEvent(ctx context.Context, event *domain.MonitorEvent) {
	select {
	case kc.eventChannel <- event:
		atomic.AddUint64(&kc.eventsReceived, 1)
	case <-ctx.Done():
		return
	default:
		atomic.AddUint64(&kc.eventsDropped, 1)
	}
}

func (kc *KernelETWConsumer) eventWorker(ctx context.Context, workerID int) {
	defer kc.wg.Done()

	log.Printf("[+] ETW event worker %d started\n", workerID)

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-kc.eventChannel:
			if !ok {
				return
			}
			kc.routeEvent(ctx, event)
		}
	}
}

func (kc *KernelETWConsumer) routeEvent(ctx context.Context, event *domain.MonitorEvent) {
	switch event.EventID {
	case 1: // ProcessCreate
		kc.eventProcessor.ProcessProcessCreate(ctx, event)
	case 2: // FileModified (write/rename to existing file)
		kc.eventProcessor.ProcessFileModified(ctx, event)
	case 10: // ProcessAccess (LSASS)
		kc.eventProcessor.ProcessLSASSAccess(ctx, event)
	case 11: // FileCreate
		kc.eventProcessor.ProcessFileCreate(ctx, event)
	case 23: // FileDelete
		kc.eventProcessor.ProcessFileDelete(ctx, event)
	}
}

func shouldEmitFileCreate(props map[string]interface{}) bool {
	// Preferred: explicit CreateDisposition field (typically Win32 values)
	if raw, ok := props["CreateDisposition"]; ok {
		if disposition, okNum := asUint32(raw); okNum {
			switch disposition {
			case 1, 2, 4, 5:
				return true
			}
			return false
		}
	}

	// Some kernels expose disposition embedded in CreateOptions high byte (NT values)
	if raw, ok := props["CreateOptions"]; ok {
		if createOptions, okNum := asUint32(raw); okNum {
			ntDisposition := (createOptions >> 24) & 0xFF
			switch ntDisposition {
			case 0, 2, 3, 4, 5:
				return true
			}
		}
	}

	return false
}

func extractInfoClass(props map[string]interface{}) (uint32, bool) {
	// Common naming variants observed across ETW payloads
	if raw, ok := props["InfoClass"]; ok {
		if v, okNum := asUint32(raw); okNum {
			return v, true
		}
	}
	if raw, ok := props["FileInfoClass"]; ok {
		if v, okNum := asUint32(raw); okNum {
			return v, true
		}
	}
	return 0, false
}

func asUint32(v interface{}) (uint32, bool) {
	switch val := v.(type) {
	case uint32:
		return val, true
	case int32:
		return uint32(val), true
	case uint64:
		return uint32(val), true
	case int64:
		return uint32(val), true
	case int:
		return uint32(val), true
	case uint:
		return uint32(val), true
	case uint16:
		return uint32(val), true
	case int16:
		return uint32(val), true
	case uint8:
		return uint32(val), true
	case int8:
		return uint32(val), true
	default:
		return 0, false
	}
}

// ============================================================================
// Cache Lookup Helpers
// ============================================================================

func (kc *KernelETWConsumer) lookupProcessGuid(pid uint32) string {
	kc.pidGuidMux.RLock()
	guid, ok := kc.pidGuidCache[pid]
	kc.pidGuidMux.RUnlock()

	if ok {
		return guid
	}

	if dead, ok := kc.getDeadProcessRecord(pid); ok && dead.ProcessGuid != "" {
		return dead.ProcessGuid
	}

	// Process started before monitoring — synthesize a fallback GUID
	guid = fmt.Sprintf("ETW-%d-0", pid)
	kc.pidGuidMux.Lock()
	kc.pidGuidCache[pid] = guid
	kc.pidGuidMux.Unlock()
	return guid
}

func (kc *KernelETWConsumer) lookupProcessImage(pid uint32) string {
	kc.imageMux.RLock()
	image, ok := kc.imageCache[pid]
	kc.imageMux.RUnlock()

	if ok {
		return image
	}

	if dead, ok := kc.getDeadProcessRecord(pid); ok && dead.Image != "" {
		return dead.Image
	}

	// Resolve on demand and cache
	image = resolveProcessImage(pid)
	if image != "" {
		kc.imageMux.Lock()
		kc.imageCache[pid] = image
		kc.imageMux.Unlock()
	}
	return image
}

func (kc *KernelETWConsumer) lookupFilePath(fileKey, fileObject uint64) string {
	kc.fileObjectMux.RLock()
	defer kc.fileObjectMux.RUnlock()

	if fileKey != 0 {
		if entry, ok := kc.fileObjectCache[fileKey]; ok {
			return entry.Path
		}
	}
	if fileObject != 0 {
		if entry, ok := kc.fileObjectCache[fileObject]; ok {
			return entry.Path
		}
	}
	return ""
}

// lookupFileObjectEntry returns the full FileObjectEntry (path + opener PID/GUID) for cross-process correlation.
func (kc *KernelETWConsumer) lookupFileObjectEntry(fileKey, fileObject uint64) (FileObjectEntry, bool) {
	kc.fileObjectMux.RLock()
	defer kc.fileObjectMux.RUnlock()

	if fileKey != 0 {
		if entry, ok := kc.fileObjectCache[fileKey]; ok {
			return entry, true
		}
	}
	if fileObject != 0 {
		if entry, ok := kc.fileObjectCache[fileObject]; ok {
			return entry, true
		}
	}
	return FileObjectEntry{}, false
}

// ============================================================================
// Background Maintenance
// ============================================================================

func (kc *KernelETWConsumer) cleanupCaches(ctx context.Context) {
	defer kc.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			kc.cleanWriteDebounceCache()
			kc.cleanFileObjectCache()
			kc.cleanDeadProcessCache()
		}
	}
}

func (kc *KernelETWConsumer) cleanWriteDebounceCache() {
	kc.writeDebounceMux.Lock()
	defer kc.writeDebounceMux.Unlock()

	cutoff := time.Now().Add(-30 * time.Second)
	for key, ts := range kc.writeDebounce {
		if ts.Before(cutoff) {
			delete(kc.writeDebounce, key)
		}
	}
}

func (kc *KernelETWConsumer) cleanFileObjectCache() {
	// FileObject cache is cleaned on FileClose events.
	// This is a safety net for handles that were never closed (leaked handles).
	// We keep a reasonable size limit instead of time-based eviction since
	// we can't timestamp cache entries without overhead.
	kc.fileObjectMux.Lock()
	defer kc.fileObjectMux.Unlock()

	const maxCacheSize = 100000
	if len(kc.fileObjectCache) > maxCacheSize {
		// Evict half the cache (random eviction due to map iteration order)
		count := 0
		for key := range kc.fileObjectCache {
			if count >= maxCacheSize/2 {
				break
			}
			delete(kc.fileObjectCache, key)
			count++
		}
		log.Printf("[ETW] FileObject cache trimmed from %d to %d entries\n",
			maxCacheSize, len(kc.fileObjectCache))
	}
}

func (kc *KernelETWConsumer) refreshLSASSPid(ctx context.Context) {
	defer kc.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pid, err := resolveLSASSPid()
			if err == nil {
				kc.lsassMux.Lock()
				if kc.lsassPID != pid {
					log.Printf("[ETW] LSASS PID updated: %d -> %d\n", kc.lsassPID, pid)
					kc.lsassPID = pid
				}
				kc.lsassMux.Unlock()
			}
		}
	}
}

func (kc *KernelETWConsumer) getDeadProcessRecord(pid uint32) (DeadProcessRecord, bool) {
	kc.deadMux.RLock()
	record, exists := kc.deadProcesses[pid]
	kc.deadMux.RUnlock()
	if !exists {
		return DeadProcessRecord{}, false
	}
	return record, true
}

func (kc *KernelETWConsumer) shouldSuppressFileEvent(pid uint32, eventTs time.Time) bool {
	if pid == 0 {
		return false
	}

	record, ok := kc.getDeadProcessRecord(pid)
	if !ok {
		return false
	}

	if eventTs.IsZero() {
		eventTs = time.Now()
	}

	if !eventTs.Before(record.DeadAt.Add(-skewTolerance)) {
		atomic.AddUint64(&kc.eventsSuppressedDeadPID, 1)
		return true
	}

	return false
}

func (kc *KernelETWConsumer) markProcessDead(pid uint32, processGuid, image string, deadAt time.Time, source string) {
	if pid == 0 {
		return
	}

	if deadAt.IsZero() {
		deadAt = time.Now()
	}
	if source == "" {
		source = "unknown"
	}

	if processGuid != "" {
		kc.pidGuidMux.Lock()
		kc.pidGuidCache[pid] = processGuid
		kc.pidGuidMux.Unlock()
	}
	if image != "" {
		kc.imageMux.Lock()
		kc.imageCache[pid] = image
		kc.imageMux.Unlock()
	}

	record := DeadProcessRecord{
		PID:         pid,
		ProcessGuid: processGuid,
		Image:       image,
		DeadAt:      deadAt,
		Source:      source,
		RetireAt:    deadAt.Add(deadPIDTTL),
	}

	kc.deadMux.Lock()
	kc.deadProcesses[pid] = record
	kc.deadMux.Unlock()
}

// MarkProcessTerminated allows response orchestration to immediately mark a process as dead.
func (kc *KernelETWConsumer) MarkProcessTerminated(pid uint32, processGuid string, image string, at time.Time, source string) {
	if source == "" {
		source = "terminate_verified"
	}

	kc.markProcessDead(pid, processGuid, image, at, source)
}

func (kc *KernelETWConsumer) cleanDeadProcessCache() {
	now := time.Now()
	expired := make(map[uint32]DeadProcessRecord)

	kc.deadMux.Lock()
	for pid, record := range kc.deadProcesses {
		if !record.RetireAt.After(now) {
			expired[pid] = record
			delete(kc.deadProcesses, pid)
		}
	}
	kc.deadMux.Unlock()

	if len(expired) == 0 {
		return
	}

	kc.pidGuidMux.Lock()
	for pid, record := range expired {
		if cached, ok := kc.pidGuidCache[pid]; ok {
			if record.ProcessGuid == "" || cached == record.ProcessGuid {
				delete(kc.pidGuidCache, pid)
			}
		}
	}
	kc.pidGuidMux.Unlock()

	kc.imageMux.Lock()
	for pid, record := range expired {
		if cached, ok := kc.imageCache[pid]; ok {
			if record.Image == "" || strings.EqualFold(cached, record.Image) {
				delete(kc.imageCache, pid)
			}
		}
	}
	kc.imageMux.Unlock()
}
