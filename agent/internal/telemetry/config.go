//go:build windows
// +build windows

package telemetry

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	ModeBaseline Mode = "baseline"
	ModeDeep     Mode = "deep"
)

const (
	defaultBaselineDir       = `C:\ProgramData\Exionis\output`
	defaultDeepCaptureDir    = `C:\ProgramData\Exionis\deep`
	defaultRollupWindowMins  = 5
	defaultDeepDurationMins  = 30
	defaultProcessRollupMins = 1
	maxDeepDuration          = 24 * time.Hour
)

type Config struct {
	Mode                 Mode
	BaselineDir          string
	DeepCaptureDir       string
	DeepDuration         time.Duration
	NetworkRollupWindow  time.Duration
	ProcessRollupWindow  time.Duration
	EnableLegacyRawFiles bool
}

func LoadConfig() Config {
	mode := parseMode(os.Getenv("EXIONIS_TELEMETRY_MODE"))
	cfg := Config{
		Mode:                 mode,
		BaselineDir:          readStringEnv("EXIONIS_BASELINE_DIR", defaultBaselineDir),
		DeepCaptureDir:       readStringEnv("EXIONIS_DEEP_DIR", defaultDeepCaptureDir),
		DeepDuration:         boundedDuration(readIntEnv("EXIONIS_DEEP_DURATION_MINUTES", defaultDeepDurationMins), time.Minute, maxDeepDuration),
		NetworkRollupWindow:  boundedDuration(readIntEnv("EXIONIS_NETWORK_ROLLUP_MINUTES", defaultRollupWindowMins), time.Minute, 30*time.Minute),
		ProcessRollupWindow:  boundedDuration(readIntEnv("EXIONIS_PROCESS_ROLLUP_MINUTES", defaultProcessRollupMins), time.Minute, 10*time.Minute),
		EnableLegacyRawFiles: readBoolEnv("EXIONIS_WRITE_LEGACY_RAW", false),
	}
	if cfg.Mode != ModeDeep {
		cfg.DeepDuration = 0
	}
	return cfg
}

func parseMode(raw string) Mode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "baseline":
		return ModeBaseline
	case "deep", "forensic":
		return ModeDeep
	default:
		return ModeBaseline
	}
}

func readStringEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func readIntEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func readBoolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func boundedDuration(raw int, unit time.Duration, max time.Duration) time.Duration {
	d := time.Duration(raw) * unit
	if d <= 0 {
		return unit
	}
	if d > max {
		return max
	}
	return d
}
