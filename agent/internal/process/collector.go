// Package process provides helpers for process enumeration and metadata.
package process

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
	"github.com/shirou/gopsutil/v3/process"
)

// ProcessInfo holds basic process metadata
type ProcessInfo struct {
	Name   string
	PID    int32
	Path   string
	CPU    float64
	Memory float32
}

// GetProcesses enumerates all running processes
func GetProcesses() []ProcessInfo {
	var result []ProcessInfo
	procs, err := process.Processes()
	if err != nil {
		fmt.Println("process error:", err)
		return result
	}
	for _, p := range procs {
		name, err := p.Name()
		if err != nil || name == "" {
			continue
		}
		pid := p.Pid
		path, err := p.Exe()
		if err != nil || path == "" {
			path = "unknown"
		}
		cpuPercent, _ := p.CPUPercent()
		memInfo, err := p.MemoryInfo()
		var memMB float32 = 0
		if err == nil && memInfo != nil {
			memMB = float32(memInfo.RSS) / 1024 / 1024
		}
		result = append(result, ProcessInfo{
			Name:   name,
			PID:    pid,
			Path:   path,
			CPU:    cpuPercent,
			Memory: memMB,
		})
	}
	time.Sleep(500 * time.Millisecond)
	return result
}

// GetCmdline retrieves the full command line for a process
func GetCmdline(pid uint32) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return ""
	}
	cmdline, err := proc.Cmdline()
	if err != nil {
		return ""
	}
	return cmdline
}

// GetExecutablePath retrieves the executable path for a process
func GetExecutablePath(pid uint32) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return ""
	}
	exe, err := proc.Exe()
	if err != nil {
		return ""
	}
	return exe
}

// GetExecutablePathWithRetry attempts to get executable path with retries
func GetExecutablePathWithRetry(pid uint32, maxAttempts int) string {
	for i := 0; i < maxAttempts; i++ {
		if path := GetExecutablePath(pid); path != "" && path != "unknown" {
			return path
		}
		if i < maxAttempts-1 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return "unknown"
}

// GetParentPID retrieves the parent process ID
func GetParentPID(pid uint32) uint32 {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0
	}
	ppid, err := proc.Ppid()
	if err != nil {
		return 0
	}
	return uint32(ppid)
}

// GetProcessNameByPID retrieves process name by PID
func GetProcessNameByPID(pid uint32) string {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return ""
	}
	name, err := proc.Name()
	if err != nil {
		return ""
	}
	return name
}

// IsProcessSigned checks if process is signed (simplified heuristic)
func IsProcessSigned(pid uint32) bool {
	exePath := GetExecutablePath(pid)
	if exePath == "" || exePath == "unknown" {
		return false
	}
	// Simplified: assume Windows system paths are signed
	lower := strings.ToLower(exePath)
	if strings.Contains(lower, `c:\windows\system32`) ||
	   strings.Contains(lower, `c:\windows\syswow64`) {
		return true
	}
	return false
}

// ComputeFileSHA256 computes SHA256 hash of a file (with size limit)
func ComputeFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	stat, err := file.Stat()
	if err != nil {
		return "", err
	}
	if stat.Size() > 100<<20 {
		return "", fmt.Errorf("file too large: %d bytes", stat.Size())
	}
	
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// IsProcessAccessible checks if process can be queried
func IsProcessAccessible(pid uint32) bool {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}
	_, err = proc.Name()
	return err == nil
}

// GetProcessUser retrieves the user SID for a process (stub)
func GetProcessUser(pid uint32) string {
	return GetProcessUserSID(pid) // or GetProcessUsername(pid) for "DOMAIN\User"
}


// ============================================================================
// GAP 1 — Username / Running User
// ============================================================================

// GetProcessUsername returns "DOMAIN\User" for the given PID.
func GetProcessUsername(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return tokenUser.User.Sid.String()
	}

	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// GetProcessUserSID returns the raw SID string for the given PID.
func GetProcessUserSID(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	return tokenUser.User.Sid.String()
}

// ============================================================================
// GAP 2 — Real Process Start Time
// ============================================================================

// GetProcessStartTime returns the real creation time of a process.
func GetProcessStartTime(pid uint32) time.Time {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(handle)

	var creation, exit, kernel, user windows.Filetime
	err = windows.GetProcessTimes(
		handle,
		&creation,
		&exit,
		&kernel,
		&user,
	)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(0, creation.Nanoseconds())
}

// ============================================================================
// GAP 3 — File Size, Creation Time, Last Modified
// ============================================================================

// FileMetadata holds binary file attributes for process enrichment.
type FileMetadata struct {
	SizeBytes    int64     `json:"size_bytes,omitempty"`
	SizeKB       int64     `json:"size_kb,omitempty"`
	CreationTime time.Time `json:"creation_time,omitempty"`
	ModifiedTime time.Time `json:"modified_time,omitempty"`
}

// GetFileMetadata returns size and timestamps for the given file path.
func GetFileMetadata(path string) (FileMetadata, bool) {
	if path == "" || path == "unknown" {
		return FileMetadata{}, false
	}

	info, err := os.Stat(path)
	if err != nil {
		return FileMetadata{}, false
	}

	meta := FileMetadata{
		SizeBytes:    info.Size(),
		SizeKB:       info.Size() / 1024,
		ModifiedTime: info.ModTime(),
	}

	if sys, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		ft := sys.CreationTime
		nsec := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
		const unixEpochOffset = 116444736000000000
		nsec = (nsec - unixEpochOffset) * 100
		if nsec > 0 {
			meta.CreationTime = time.Unix(0, nsec)
		}
	}

	return meta, true
}

// ============================================================================
// GAP 4 — Orphan Process Detection
// ============================================================================

// IsOrphanProcess returns true if the process's parent no longer exists.
func IsOrphanProcess(pid uint32, livePIDs map[uint32]bool) bool {
	ppid := GetParentPID(pid)
	if ppid == 0 || ppid == 4 {
		return false
	}
	return !livePIDs[ppid]
}

// BuildLivePIDSet returns a set of all currently running PIDs.
func BuildLivePIDSet() map[uint32]bool {
	procs := GetProcesses()
	set := make(map[uint32]bool, len(procs))
	for _, p := range procs {
		set[uint32(p.PID)] = true
	}
	return set
}

// ============================================================================
// GAP 5 — Process Architecture (32-bit vs 64-bit)
// ============================================================================

var (
	modKernel32         = syscall.NewLazyDLL("kernel32.dll")
	procIsWow64Process2 = modKernel32.NewProc("IsWow64Process2")
)

// GetProcessArchitecture returns "x64", "x86", or "unknown".
func GetProcessArchitecture(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return "unknown"
	}
	defer windows.CloseHandle(handle)

	var processMachine, nativeMachine uint16
	ret, _, _ := procIsWow64Process2.Call(
		uintptr(unsafe.Pointer(handle)),
		uintptr(unsafe.Pointer(&processMachine)),
		uintptr(unsafe.Pointer(&nativeMachine)),
	)
	if ret == 0 {
		return "unknown"
	}

	switch processMachine {
	case 0x014c:
		return "x86"
	case 0x8664:
		return "x64"
	case 0xAA64:
		return "arm64"
	case 0x0000:
		switch nativeMachine {
		case 0x8664:
			return "x64"
		case 0xAA64:
			return "arm64"
		}
	}
	return "unknown"
}