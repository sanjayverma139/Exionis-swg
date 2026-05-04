//go:build windows
// +build windows

package output

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GzipNDJSONWriter writes newline-delimited JSON to a gzip-compressed file.
type GzipNDJSONWriter struct {
	mu       sync.Mutex
	file     *os.File
	gz       *gzip.Writer
	filePath string
}

// NewGzipNDJSONWriter creates a compressed writer at the provided path.
func NewGzipNDJSONWriter(path string) (*GzipNDJSONWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create deep capture dir: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open deep capture file: %w", err)
	}
	gz := gzip.NewWriter(file)
	return &GzipNDJSONWriter{
		file:     file,
		gz:       gz,
		filePath: path,
	}, nil
}

// Path returns the absolute path of the underlying capture file.
func (w *GzipNDJSONWriter) Path() string {
	return w.filePath
}

// Write appends one JSON record.
func (w *GzipNDJSONWriter) Write(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.gz == nil {
		return fmt.Errorf("deep capture writer is closed")
	}

	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal deep capture record: %w", err)
	}
	b = append(b, '\n')
	if _, err := w.gz.Write(b); err != nil {
		return fmt.Errorf("write deep capture record: %w", err)
	}
	if err := w.gz.Flush(); err != nil {
		return fmt.Errorf("flush deep capture record: %w", err)
	}
	return nil
}

// Flush forces pending compressed bytes to disk.
func (w *GzipNDJSONWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gz == nil {
		return nil
	}
	if err := w.gz.Flush(); err != nil {
		return err
	}
	return w.file.Sync()
}

// Close finalizes and closes the compressed file.
func (w *GzipNDJSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var firstErr error
	if w.gz != nil {
		if err := w.gz.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		w.gz = nil
	}
	if w.file != nil {
		if err := w.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		w.file = nil
	}
	return firstErr
}

// DeepCaptureFilePath builds a session-scoped deep capture file path.
func DeepCaptureFilePath(baseDir, deviceID string, startedAt time.Time) string {
	safe := sanitizeDeviceID(deviceID)
	return filepath.Join(baseDir, fmt.Sprintf("deep_capture_%s_%s.ndjson.gz", safe, startedAt.Format("20060102-150405")))
}
