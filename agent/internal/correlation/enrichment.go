package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"exionis/internal/process"
)

func (e *Engine) enrichAsync(pid uint32, imageName string) {
	go func() {
		enrichSem <- struct{}{}
		defer func() { <-enrichSem }()

		exePath := e.retryResolvePath(pid, 5, 20*time.Millisecond)
		if exePath == "" || exePath == "unknown" {
			exePath = parseExecutablePathFromCmdline(process.GetCmdline(pid))
		}
		if exePath == "" || exePath == "unknown" {
			return
		}

		var hash string
		if stat, err := os.Stat(exePath); err == nil && stat.Size() <= 100<<20 {
			hash = computeSHA256Safe(exePath)
		}

		tableMu.Lock()
		if proc, ok := processTable[pid]; ok && proc.IsAlive {
			changed := false
			if proc.Enrichment.ExecutablePath != exePath || proc.ImagePath != exePath {
				proc.Enrichment.ExecutablePath = exePath
				proc.ImagePath = exePath
				changed = true
			}
			if hash != "" && proc.Enrichment.SHA256Hash != hash {
				proc.Enrichment.SHA256Hash = hash
				changed = true
			}
			isSystem := isSystemProcess(exePath)
			if proc.Enrichment.IsSystem != isSystem {
				proc.Enrichment.IsSystem = isSystem
				changed = true
			}
			snapshot := *proc
			tableMu.Unlock()
			if changed {
				emitProcessEnrichmentUpdate(&snapshot)
			}
			return
		}
		tableMu.Unlock()
	}()
}

func (e *Engine) retryResolvePath(pid uint32, attempts int, delay time.Duration) string {
	for i := 0; i < attempts; i++ {
		if path := process.GetExecutablePath(pid); path != "" && path != "unknown" {
			return path
		}
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return ""
}

func enrichProcessAsync(proc *ProcessInfo, imageName string) {
	enrichment := enrichProcessAtStart(proc.PID, imageName)
	tableMu.Lock()
	if p, ok := processTable[proc.PID]; ok && p.IsAlive {
		p.Enrichment = enrichment
		if enrichment.ExecutablePath != "" {
			p.ImagePath = enrichment.ExecutablePath
		}
	}
	tableMu.Unlock()
}

func enrichProcessAtStart(pid uint32, imageName string) ProcessEnrichment {
	enrich := ProcessEnrichment{IsSystem: false}
	if exePath := process.GetExecutablePathWithRetry(pid, 10); exePath != "" && exePath != "unknown" {
		enrich.ExecutablePath = exePath
		enrich.IsSystem = isSystemProcess(exePath)
	}
	if enrich.ExecutablePath == "" {
		if exePath := parseExecutablePathFromCmdline(process.GetCmdline(pid)); exePath != "" {
			enrich.ExecutablePath = exePath
			enrich.IsSystem = isSystemProcess(exePath)
		}
	}
	if enrich.ExecutablePath != "" {
		if hash, err := computeFileSHA256(enrich.ExecutablePath); err == nil {
			enrich.SHA256Hash = hash
		}
	}
	enrich.Username = process.GetProcessUsername(pid)
	enrich.UserSID = process.GetProcessUserSID(pid)
	return enrich
}

func parseExecutablePathFromCmdline(cmdline string) string {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return ""
	}
	var candidate string
	if strings.HasPrefix(cmdline, `"`) {
		trimmed := strings.TrimPrefix(cmdline, `"`)
		if idx := strings.Index(trimmed, `"`); idx >= 0 {
			candidate = trimmed[:idx]
		}
	} else {
		candidate = strings.Fields(cmdline)[0]
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	if _, err := os.Stat(candidate); err != nil {
		return ""
	}
	return candidate
}

func (e *Engine) tryFallbackEnrichment(pid uint32, proc *ProcessInfo) {
	path := process.GetExecutablePath(pid)
	if path == "" || path == "unknown" {
		path = parseExecutablePathFromCmdline(proc.Cmdline)
	}
	if path == "" || path == "unknown" {
		return
	}
	hash := computeSHA256Safe(path)
	tableMu.Lock()
	if p, ok := processTable[pid]; ok {
		if p.Enrichment.ExecutablePath == "" {
			p.Enrichment.ExecutablePath = path
			p.ImagePath = path
			p.Enrichment.SHA256Hash = hash
			p.Enrichment.IsSystem = isSystemProcess(path)
		}
		snap := *p
		tableMu.Unlock()
		emitProcessEnrichmentUpdate(&snap)
		return
	}
	tableMu.Unlock()
}

func computeSHA256Safe(path string) string {
	hash, err := computeFileSHA256(path)
	if err != nil {
		return ""
	}
	return hash
}

func computeFileSHA256(path string) (string, error) {
	hashCacheMu.RLock()
	if h, ok := hashCache[path]; ok {
		hashCacheMu.RUnlock()
		return h, nil
	}
	hashCacheMu.RUnlock()

	hashSem <- struct{}{}
	defer func() { <-hashSem }()

	hashCacheMu.RLock()
	if h, ok := hashCache[path]; ok {
		hashCacheMu.RUnlock()
		return h, nil
	}
	hashCacheMu.RUnlock()

	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	if stat.Size() > 100<<20 {
		return "", fmt.Errorf("file too large: %d bytes", stat.Size())
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	hashCacheMu.Lock()
	hashCache[path] = hash
	if len(hashCache) > hashCacheLimit {
		count := 0
		for k := range hashCache {
			delete(hashCache, k)
			if count++; count >= hashCacheLimit/10 {
				break
			}
		}
	}
	hashCacheMu.Unlock()
	return hash, nil
}

func isSystemProcess(imagePath string) bool {
	if imagePath == "" {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(imagePath, "/", `\`))
	return strings.Contains(normalized, `c:\windows\system32`) ||
		strings.Contains(normalized, `c:\windows\syswow64`) ||
		strings.Contains(normalized, `\systemroot\`)
}
