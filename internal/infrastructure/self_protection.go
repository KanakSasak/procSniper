//go:build windows
// +build windows

package infrastructure

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows constants for process/thread ACL hardening
const (
	seKernelObject                   = 6          // SE_KERNEL_OBJECT
	daclSecurityInformation          = 0x00000004 // DACL_SECURITY_INFORMATION
	protectedDaclSecurityInformation = 0x80000000 // PROTECTED_DACL_SECURITY_INFORMATION
	aclRevisionConst                 = 2          // ACL_REVISION

	// Dangerous process access rights denied for Everyone
	denyProcessAccess = 0x0001 | // PROCESS_TERMINATE
		0x0002 | // PROCESS_CREATE_THREAD
		0x0008 | // PROCESS_VM_OPERATION
		0x0020 | // PROCESS_VM_WRITE
		0x0800 | // PROCESS_SUSPEND_RESUME
		0x40000 | // WRITE_DAC
		0x80000 // WRITE_OWNER

	// Dangerous thread access rights denied for Everyone
	denyThreadAccess = 0x0001 | // THREAD_TERMINATE
		0x0002 | // THREAD_SUSPEND_RESUME
		0x0010 | // THREAD_SET_CONTEXT
		0x0020 | // THREAD_SET_INFORMATION
		0x0080 | // THREAD_SET_THREAD_TOKEN
		0x40000 | // WRITE_DAC
		0x80000 // WRITE_OWNER
)

var (
	modAdvapi32SelfProtect  = windows.NewLazySystemDLL("advapi32.dll")
	procSetSecurityInfo     = modAdvapi32SelfProtect.NewProc("SetSecurityInfo")
	procInitializeAcl       = modAdvapi32SelfProtect.NewProc("InitializeAcl")
	procAddAccessDeniedAce  = modAdvapi32SelfProtect.NewProc("AddAccessDeniedAce")
)

// buildDenyACL creates an ACL with a single Deny ACE for the Everyone (World)
// SID that blocks the specified access mask. An explicit Deny ACE is stronger
// than an empty DACL because it prevents callers with SeTakeOwnershipPrivilege
// from taking ownership and re-granting access (WRITE_DAC and WRITE_OWNER are
// explicitly denied).
func buildDenyACL(denyMask uint32) ([]byte, error) {
	worldSid, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return nil, fmt.Errorf("CreateWellKnownSid(WinWorldSid) failed: %w", err)
	}

	sidLen := int(worldSid.Len())

	// ACL size = header(8) + ACE(ACE_HEADER(4) + ACCESS_MASK(4) + SidStart(4)) - DWORD(4) + sidLen
	// Simplified: 8 + 8 + sidLen, DWORD-aligned
	aclSize := 8 + 8 + sidLen
	aclSize = (aclSize + 3) &^ 3

	aclBuf := make([]byte, aclSize)

	ret, _, callErr := procInitializeAcl.Call(
		uintptr(unsafe.Pointer(&aclBuf[0])),
		uintptr(aclSize),
		uintptr(aclRevisionConst),
	)
	if ret == 0 {
		return nil, fmt.Errorf("InitializeAcl failed: %w", callErr)
	}

	ret, _, callErr = procAddAccessDeniedAce.Call(
		uintptr(unsafe.Pointer(&aclBuf[0])),
		uintptr(aclRevisionConst),
		uintptr(denyMask),
		uintptr(unsafe.Pointer(worldSid)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("AddAccessDeniedAce failed: %w", callErr)
	}

	return aclBuf, nil
}

// ProtectCurrentProcess hardens the current process against external
// termination, injection, and DACL tampering by applying an explicit Deny ACE
// for the Everyone SID.
//
// Denied operations:
//   - PROCESS_TERMINATE         — blocks TerminateProcess / NtTerminateProcess
//   - PROCESS_CREATE_THREAD     — blocks remote thread injection
//   - PROCESS_VM_OPERATION      — blocks VirtualProtectEx
//   - PROCESS_VM_WRITE          — blocks WriteProcessMemory
//   - PROCESS_SUSPEND_RESUME    — blocks NtSuspendProcess
//   - WRITE_DAC                 — blocks DACL modification (re-granting access)
//   - WRITE_OWNER               — blocks ownership takeover
//
// Important notes:
//   - SYSTEM and kernel-mode callers bypass DACLs, so Windows integrity is preserved.
//   - Console signals (Ctrl+C) still work via SetConsoleCtrlHandler, not handle access.
//   - Task Manager running as SYSTEM can still terminate the process.
//   - Our own goroutines and Go runtime are unaffected (they use pseudo-handles).
func ProtectCurrentProcess() error {
	aclBuf, err := buildDenyACL(denyProcessAccess)
	if err != nil {
		return fmt.Errorf("failed to build process deny ACL: %w", err)
	}

	handle := windows.CurrentProcess()
	ret, _, callErr := procSetSecurityInfo.Call(
		uintptr(handle),
		uintptr(seKernelObject),
		uintptr(daclSecurityInformation|protectedDaclSecurityInformation),
		0, // owner SID — unchanged
		0, // group SID — unchanged
		uintptr(unsafe.Pointer(&aclBuf[0])),
		0, // SACL — unchanged
	)
	if ret != 0 {
		return fmt.Errorf("SetSecurityInfo failed with error code %d: %w", ret, callErr)
	}

	log.Println("[+] Process self-protection enabled (Deny ACE for Everyone)")
	log.Println("[+] Blocked: TERMINATE, CREATE_THREAD, VM_WRITE, VM_OP, SUSPEND, WRITE_DAC, WRITE_OWNER")
	return nil
}

// ProtectCurrentThreads applies the same deny-ACE hardening to all OS threads
// belonging to the current process. This prevents ransomware from bypassing
// process-level protection by targeting individual threads (OpenThread +
// TerminateThread, thread injection via SetThreadContext, etc.).
func ProtectCurrentThreads() error {
	aclBuf, err := buildDenyACL(denyThreadAccess)
	if err != nil {
		return fmt.Errorf("failed to build thread deny ACL: %w", err)
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: %w", err)
	}
	defer windows.CloseHandle(snap)

	currentPID := uint32(os.Getpid())

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	if err := windows.Thread32First(snap, &te); err != nil {
		return fmt.Errorf("Thread32First failed: %w", err)
	}

	protected := 0
	for {
		if te.OwnerProcessID == currentPID {
			// WRITE_DAC is needed to modify the thread's DACL
			th, openErr := windows.OpenThread(windows.WRITE_DAC, false, te.ThreadID)
			if openErr == nil {
				ret, _, _ := procSetSecurityInfo.Call(
					uintptr(th),
					uintptr(seKernelObject),
					uintptr(daclSecurityInformation|protectedDaclSecurityInformation),
					0, 0,
					uintptr(unsafe.Pointer(&aclBuf[0])),
					0,
				)
				if ret == 0 {
					protected++
				}
				windows.CloseHandle(th)
			}
		}
		if err := windows.Thread32Next(snap, &te); err != nil {
			break
		}
	}

	log.Printf("[+] Thread self-protection enabled (%d threads hardened)", protected)
	return nil
}

// StartPeriodicThreadProtection re-applies thread DACL hardening every 30
// seconds to catch new OS threads created by the Go runtime. Runs until the
// context is cancelled.
func StartPeriodicThreadProtection(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ProtectCurrentThreads(); err != nil {
				log.Printf("[!] Periodic thread protection failed: %v", err)
			}
		}
	}
}
