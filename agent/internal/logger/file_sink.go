// internal/logger/file_sink.go
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileSink writes NDJSON events to rotating log files
type FileSink struct {
	dir          string
	prefix       string
	maxSizeBytes int64
	maxFiles     int
	currentFile  *os.File
	bytesWritten int64
	mu           sync.Mutex
}

// NewFileSink creates a new rotating file logger
func NewFileSink(logDir, prefix string, maxSizeMB, maxFiles int) (*FileSink, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	
	sink := &FileSink{
		dir:          logDir,
		prefix:       prefix,
		maxSizeBytes: int64(maxSizeMB) * 1024 * 1024,
		maxFiles:     maxFiles,
	}
	
	// Rotate old logs on startup
	sink.rotateOldLogs()
	
	// Open new file
	if err := sink.openNewFile(); err != nil {
		return nil, err
	}
	
	return sink, nil
}

// WriteEvent writes a single event as NDJSON
func (s *FileSink) WriteEvent(event interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	jsonBytes = append(jsonBytes, '\n')
	
	// Rotate if file too large
	if s.bytesWritten+int64(len(jsonBytes)) > s.maxSizeBytes {
		if err := s.rotate(); err != nil {
			// Log error but continue writing to current file
			fmt.Fprintf(os.Stderr, "[Exionis-Logger] Rotate error: %v\n", err)
		}
	}
	
	_, err = s.currentFile.Write(jsonBytes)
	if err != nil {
		return fmt.Errorf("write log: %w", err)
	}
	s.bytesWritten += int64(len(jsonBytes))
	
	return nil
}

// rotate closes current file, renames it, and opens a new one
func (s *FileSink) rotate() error {
	if s.currentFile != nil {
		s.currentFile.Close()
	}
	
	// Rename current file with timestamp
	timestamp := time.Now().Format("20060102-150405")
	oldPath := s.currentFilePath()
	newPath := fmt.Sprintf("%s.%s.ndjson", strings.TrimSuffix(oldPath, ".ndjson"), timestamp)
	
	if err := os.Rename(oldPath, newPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("rename log: %w", err)
	}
	
	// Clean up old files
	s.cleanupOldLogs()
	
	// Open new file
	return s.openNewFile()
}

func (s *FileSink) currentFilePath() string {
	return filepath.Join(s.dir, fmt.Sprintf("%s.ndjson", s.prefix))
}

func (s *FileSink) openNewFile() error {
	f, err := os.OpenFile(s.currentFilePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	s.currentFile = f
	
	// Get current size
	if stat, err := f.Stat(); err == nil {
		s.bytesWritten = stat.Size()
	}
	return nil
}

func (s *FileSink) rotateOldLogs() {
	// Find existing log files matching pattern
	files, err := filepath.Glob(filepath.Join(s.dir, fmt.Sprintf("%s.*.ndjson", s.prefix)))
	if err != nil {
		return
	}
	
	// Sort by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		info1, _ := os.Stat(files[i])
		info2, _ := os.Stat(files[j])
		if info1 == nil || info2 == nil {
			return files[i] < files[j]
		}
		return info1.ModTime().Before(info2.ModTime())
	})
	
	// Delete oldest files beyond maxFiles limit
	for len(files) >= s.maxFiles {
		os.Remove(files[0])
		files = files[1:]
	}
}

func (s *FileSink) cleanupOldLogs() {
	files, err := filepath.Glob(filepath.Join(s.dir, fmt.Sprintf("%s.*.ndjson", s.prefix)))
	if err != nil {
		return
	}
	
	// Sort by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		info1, _ := os.Stat(files[i])
		info2, _ := os.Stat(files[j])
		if info1 == nil || info2 == nil {
			return files[i] < files[j]
		}
		return info1.ModTime().Before(info2.ModTime())
	})
	
	// Keep only maxFiles-1 rotated files (current file doesn't count)
	for len(files) >= s.maxFiles {
		os.Remove(files[0])
		files = files[1:]
	}
}

// Close closes the current log file
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentFile != nil {
		return s.currentFile.Close()
	}
	return nil
}