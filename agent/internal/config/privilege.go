package config

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken = advapi32.NewProc("OpenProcessToken")
	procLookupPrivilege  = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustToken      = advapi32.NewProc("AdjustTokenPrivileges")
)

const (
	TOKEN_ADJUST_PRIVS   = 0x0020
	TOKEN_QUERY          = 0x0008
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

func enablePrivilege(token syscall.Handle, privilege string) error {
	var luid LUID

	privName, err := syscall.UTF16PtrFromString(privilege)
	if err != nil {
		return fmt.Errorf("UTF16 conversion failed for %s: %w", privilege, err)
	}

	r1, _, callErr := procLookupPrivilege.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r1 == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed for %s: %v", privilege, callErr)
	}

	tp := TokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	r1, _, callErr = procAdjustToken.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed for %s: %v", privilege, callErr)
	}

	fmt.Printf("[Exionis] %s enabled successfully\n", privilege)
	return nil
}

func EnableSeDebugPrivilege() error {

	// Get current process handle (FIXED)
	proc, _ := syscall.GetCurrentProcess()

	var token syscall.Handle

	// Open process token
	r1, _, err := procOpenProcessToken.Call(
		uintptr(proc),
		uintptr(TOKEN_ADJUST_PRIVS|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)

	if r1 == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer syscall.CloseHandle(token)

	privileges := []string{
		"SeDebugPrivilege",
		"SeSystemProfilePrivilege",
	}

	for _, privilege := range privileges {
		if err := enablePrivilege(token, privilege); err != nil {
			return err
		}
	}

	return nil
}
