// Package config handles Windows privilege escalation for ETW access.
package config

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenProcessToken         = modadvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW    = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges    = modadvapi32.NewProc("AdjustTokenPrivileges")
	procGetCurrentProcess        = modkernel32.NewProc("GetCurrentProcess")
)

const (
	SE_DEBUG_NAME       = "SeDebugPrivilege"
	SE_SYSTEM_PROFILE   = "SeSystemProfilePrivilege"
	TOKEN_ADJUST_PRIV   = 0x0020
	TOKEN_QUERY         = 0x0008
	SE_PRIVILEGE_ENABLED = 0x00000002
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

type TokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]LUIDAndAttributes
}

// EnableSeDebugPrivilege grants SeDebugPrivilege for process enumeration.
func EnableSeDebugPrivilege() error {
	return enablePrivilege(SE_DEBUG_NAME)
}

// EnableSeSystemProfilePrivilege grants SeSystemProfilePrivilege for kernel ETW.
func EnableSeSystemProfilePrivilege() error {
	return enablePrivilege(SE_SYSTEM_PROFILE)
}

// enablePrivilege is the internal helper for privilege escalation.
func enablePrivilege(privilege string) error {
	var tokenHandle syscall.Token
	var luid LUID

	// Get current process handle
	currentProc, _, err := procGetCurrentProcess.Call()
	if currentProc == 0 {
		return fmt.Errorf("GetCurrentProcess failed: %v", err)
	}

	// Open process token
	ret, _, err := procOpenProcessToken.Call(
		currentProc,
		uintptr(TOKEN_ADJUST_PRIV|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&tokenHandle)),
	)
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(tokenHandle))

	// Lookup privilege LUID
	privName, err := syscall.UTF16PtrFromString(privilege)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %v", err)
	}

	ret, _, err = procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValueW failed for %s: %v", privilege, err)
	}

	// Adjust token privileges
	tp := TokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed for %s: %v", privilege, err)
	}

	return nil
}

// EnableAllPrivileges enables all required privileges for Exionis agent.
func EnableAllPrivileges() error {
	if err := EnableSeDebugPrivilege(); err != nil {
		return fmt.Errorf("failed to enable SeDebugPrivilege: %w", err)
	}
	if err := EnableSeSystemProfilePrivilege(); err != nil {
		return fmt.Errorf("failed to enable SeSystemProfilePrivilege: %w", err)
	}
	return nil
}