//go:build windows
// +build windows

package infrastructure

import (
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows constants for process ACL hardening
const (
	seKernelObject                   = 6          // SE_KERNEL_OBJECT
	daclSecurityInformation          = 0x00000004 // DACL_SECURITY_INFORMATION
	protectedDaclSecurityInformation = 0x80000000 // PROTECTED_DACL_SECURITY_INFORMATION
	aclRevisionConst                 = 2          // ACL_REVISION
)

var (
	modAdvapi32SelfProtect = windows.NewLazySystemDLL("advapi32.dll")
	procSetSecurityInfo    = modAdvapi32SelfProtect.NewProc("SetSecurityInfo")
	procInitializeAcl      = modAdvapi32SelfProtect.NewProc("InitializeAcl")
)

// winACL mirrors the native Windows ACL header structure (8 bytes).
type winACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// ProtectCurrentProcess hardens the current process against external termination
// by setting an empty DACL on the process object.
//
// An empty DACL means no access is explicitly granted via the discretionary
// access control list.  External callers (including ransomware using
// TerminateProcess / NtTerminateProcess) cannot obtain a handle to our process
// because every access check against the empty DACL is denied.
//
// Important notes:
//   - SYSTEM and kernel-mode callers bypass DACLs, so Windows integrity is preserved.
//   - Console signals (Ctrl+C) still work because they use SetConsoleCtrlHandler,
//     not process handle access.
//   - Task Manager running as SYSTEM can still terminate the process.
//   - Our own goroutines and Go runtime are unaffected (they use pseudo-handles).
func ProtectCurrentProcess() error {
	// Create an empty ACL — no ACEs, just the 8-byte header.
	var emptyACL winACL
	ret, _, err := procInitializeAcl.Call(
		uintptr(unsafe.Pointer(&emptyACL)),
		uintptr(unsafe.Sizeof(emptyACL)),
		uintptr(aclRevisionConst),
	)
	if ret == 0 {
		return fmt.Errorf("InitializeAcl failed: %w", err)
	}

	// Apply the empty DACL to the current process.
	// PROTECTED_DACL prevents inherited ACEs from the user's token defaults.
	handle := windows.CurrentProcess()
	ret, _, err = procSetSecurityInfo.Call(
		uintptr(handle),
		uintptr(seKernelObject),
		uintptr(daclSecurityInformation|protectedDaclSecurityInformation),
		0, // owner SID — unchanged
		0, // group SID — unchanged
		uintptr(unsafe.Pointer(&emptyACL)),
		0, // SACL — unchanged
	)
	if ret != 0 {
		return fmt.Errorf("SetSecurityInfo failed with error code %d: %w", ret, err)
	}

	log.Println("[+] Process self-protection enabled (DACL hardened)")
	log.Println("[+] External process termination blocked (TerminateProcess/NtTerminateProcess)")
	return nil
}
