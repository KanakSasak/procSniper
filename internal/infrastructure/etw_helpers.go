//go:build windows

package infrastructure

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants for process information
const (
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_VM_READ_ACCESS           = 0x0010
)

// Windows API functions for process and path resolution
var (
	modKernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	modNtdll                       = windows.NewLazySystemDLL("ntdll.dll")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
	procQueryDosDeviceW            = modKernel32.NewProc("QueryDosDeviceW")
	procCreateToolhelp32Snapshot   = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW             = modKernel32.NewProc("Process32NextW")
	procNtQueryInformationProcess  = modNtdll.NewProc("NtQueryInformationProcess")
	procReadProcessMemory          = modKernel32.NewProc("ReadProcessMemory")
)

// Toolhelp32 constants
const (
	TH32CS_SNAPPROCESS = 0x00000002
	MAX_PATH           = 260
)

// PROCESSENTRY32W for process enumeration
type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

// PEB structures for command line reading
type processBasicInformation struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

// devicePathCache caches NT device path -> drive letter mappings
var (
	devicePathMap     map[string]string
	devicePathMapOnce sync.Once
)

// buildDevicePathMap builds a mapping from NT device paths to drive letters
func buildDevicePathMap() {
	devicePathMapOnce.Do(func() {
		devicePathMap = make(map[string]string)

		// Get all logical drives
		drives, err := windows.GetLogicalDrives()
		if err != nil {
			return
		}

		buf := make([]uint16, 512)
		for i := 0; i < 26; i++ {
			if drives&(1<<uint(i)) == 0 {
				continue
			}
			driveLetter := string(rune('A'+i)) + ":"
			drivePtr, _ := syscall.UTF16PtrFromString(driveLetter)

			ret, _, _ := procQueryDosDeviceW.Call(
				uintptr(unsafe.Pointer(drivePtr)),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(len(buf)),
			)
			if ret > 0 {
				devicePath := windows.UTF16ToString(buf)
				devicePathMap[strings.ToLower(devicePath)] = driveLetter
			}
		}
	})
}

// convertDevicePath converts an NT device path to a DOS path.
// e.g., \Device\HarddiskVolume3\Users\foo\file.txt -> C:\Users\foo\file.txt
func convertDevicePath(ntPath string) string {
	if ntPath == "" {
		return ntPath
	}

	// If it already looks like a DOS path, return as-is
	if len(ntPath) >= 2 && ntPath[1] == ':' {
		return ntPath
	}

	buildDevicePathMap()

	lower := strings.ToLower(ntPath)
	for devicePath, driveLetter := range devicePathMap {
		if strings.HasPrefix(lower, devicePath) {
			return driveLetter + ntPath[len(devicePath):]
		}
	}

	// If no mapping found, try to strip common prefixes
	if strings.HasPrefix(lower, `\device\harddiskvolume`) {
		// Find the next backslash after the volume number
		idx := strings.Index(ntPath[len(`\Device\HarddiskVolume`):], `\`)
		if idx >= 0 {
			remainder := ntPath[len(`\Device\HarddiskVolume`)+idx:]
			return "C:" + remainder // fallback to C:
		}
	}

	return ntPath
}

// resolveProcessImage resolves the full image path for a process by PID.
func resolveProcessImage(pid uint32) string {
	handle, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret != 0 {
		return windows.UTF16ToString(buf[:size])
	}
	return ""
}

// resolveCommandLine attempts to read the command line of a process from its PEB.
func resolveCommandLine(pid uint32) string {
	handle, err := windows.OpenProcess(
		PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ_ACCESS,
		false,
		pid,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	// Get PEB address via NtQueryInformationProcess
	var pbi processBasicInformation
	var returnLength uint32
	ret, _, _ := procNtQueryInformationProcess.Call(
		uintptr(handle),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret != 0 { // NTSTATUS != STATUS_SUCCESS
		return ""
	}

	// Read RTL_USER_PROCESS_PARAMETERS pointer from PEB
	// PEB offset for ProcessParameters is 0x20 on 64-bit
	var processParametersAddr uintptr
	var bytesRead uintptr
	pebOffset := pbi.PebBaseAddress + 0x20
	ret, _, _ = procReadProcessMemory.Call(
		uintptr(handle),
		pebOffset,
		uintptr(unsafe.Pointer(&processParametersAddr)),
		unsafe.Sizeof(processParametersAddr),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return ""
	}

	// Read CommandLine UNICODE_STRING from RTL_USER_PROCESS_PARAMETERS
	// Offset for CommandLine is 0x70 on 64-bit
	var cmdLine unicodeString
	cmdLineOffset := processParametersAddr + 0x70
	ret, _, _ = procReadProcessMemory.Call(
		uintptr(handle),
		cmdLineOffset,
		uintptr(unsafe.Pointer(&cmdLine)),
		unsafe.Sizeof(cmdLine),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 || cmdLine.Length == 0 {
		return ""
	}

	// Read the actual command line string
	cmdLineBuf := make([]uint16, cmdLine.Length/2)
	ret, _, _ = procReadProcessMemory.Call(
		uintptr(handle),
		cmdLine.Buffer,
		uintptr(unsafe.Pointer(&cmdLineBuf[0])),
		uintptr(cmdLine.Length),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if ret == 0 {
		return ""
	}

	return windows.UTF16ToString(cmdLineBuf)
}

// resolveLSASSPid finds the PID of lsass.exe using a process snapshot.
func resolveLSASSPid() (uint32, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		TH32CS_SNAPPROCESS,
		0,
	)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procProcess32FirstW.Call(
		snapshot,
		uintptr(unsafe.Pointer(&entry)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("Process32First failed: %w", err)
	}

	for {
		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exeName, "lsass.exe") {
			return entry.ProcessID, nil
		}

		ret, _, _ = procProcess32NextW.Call(
			snapshot,
			uintptr(unsafe.Pointer(&entry)),
		)
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("lsass.exe not found")
}

// resolveParentPID looks up the parent PID for a given process using a snapshot.
// Returns 0 if the process is not found or on error.
func resolveParentPID(pid uint32) uint32 {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		_ = err
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}
	for {
		if entry.ProcessID == pid {
			return entry.ParentProcessID
		}
		ret, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return 0
}

// getStringProp safely extracts a string property from ETW event properties.
func getStringProp(props map[string]interface{}, key string) string {
	if v, ok := props[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}

// getUint32Prop safely extracts a uint32 property from ETW event properties.
func getUint32Prop(props map[string]interface{}, key string) uint32 {
	if v, ok := props[key]; ok {
		switch val := v.(type) {
		case uint32:
			return val
		case int32:
			return uint32(val)
		case uint64:
			return uint32(val)
		case int64:
			return uint32(val)
		case int:
			return uint32(val)
		case uint:
			return uint32(val)
		case uint16:
			return uint32(val)
		case uint8:
			return uint32(val)
		}
	}
	return 0
}

// getUint64Prop safely extracts a uint64 property from ETW event properties.
func getUint64Prop(props map[string]interface{}, key string) uint64 {
	if v, ok := props[key]; ok {
		switch val := v.(type) {
		case uint64:
			return val
		case int64:
			return uint64(val)
		case uint32:
			return uint64(val)
		case int32:
			return uint64(val)
		case uintptr:
			return uint64(val)
		case int:
			return uint64(val)
		case uint:
			return uint64(val)
		}
	}
	return 0
}

// getHostname returns the computer hostname (cached).
var (
	cachedHostname     string
	cachedHostnameOnce sync.Once
)

func getHostname() string {
	cachedHostnameOnce.Do(func() {
		cachedHostname, _ = os.Hostname()
	})
	return cachedHostname
}
