// File: internal/process/collector.go
package process

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessInfo struct {
	Name   string
	PID    int32
	Path   string
	CPU    float64
	Memory float32
}

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

// GetCmdline retrieves the full command line for a given PID
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

// GetExecutablePath returns the full image path for a PID
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

// GetExecutablePathWithRetry queries path with 3 attempts for short-lived processes
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

// IsProcessSigned is a placeholder for Phase 3 signature verification
func IsProcessSigned(pid uint32) bool {
	// Phase 2: Skip signature verification (requires CGO + CryptoAPI)
	// Phase 3: Implement using WinVerifyTrust with proper syscall wrappers
	return false
}

// ComputeFileSHA256 exports SHA256 computation
func ComputeFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}