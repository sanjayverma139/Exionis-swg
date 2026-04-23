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
	return ""
}