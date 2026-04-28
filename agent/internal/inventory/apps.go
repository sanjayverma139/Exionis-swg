package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// InstalledApp represents an application from Windows uninstall registry data.
type InstalledApp struct {
	Name            string `json:"display_name"`
	Version         string `json:"display_version"`
	Publisher       string `json:"publisher"`
	InstallLocation string `json:"install_location,omitempty"`
	InstallDate     string `json:"install_date,omitempty"`
	UninstallString string `json:"uninstall_string,omitempty"`
	SizeKB          uint64 `json:"estimated_size_kb,omitempty"`
	ActualSizeKB    uint64 `json:"actual_size_kb,omitempty"`
	IsSystem        bool   `json:"is_system_component"`
	Source          string `json:"registry_source"`
	LastModified    string `json:"last_modified,omitempty"`
	FileHash        string `json:"file_hash,omitempty"`
	InstallSource   string `json:"install_source,omitempty"`
	RiskScore       int    `json:"risk_score,omitempty"`
}

// CollectInstalledApps scans Windows registry hives for installed applications.
func CollectInstalledApps() []InstalledApp {
	var apps []InstalledApp
	seen := make(map[string]bool)

	sources := []struct {
		key  registry.Key
		path string
		src  string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "HKLM"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "HKCU"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "HKLM_WoW64"},
	}

	for _, src := range sources {
		kk, err := registry.OpenKey(src.key, src.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		subkeys, err := kk.ReadSubKeyNames(-1)
		kk.Close()
		if err != nil {
			continue
		}

		for _, sub := range subkeys {
			app, err := readAppEntry(src.key, src.path+`\`+sub, src.src)
			if err != nil || app.Name == "" {
				continue
			}
			if isNoiseComponent(app.Name, app.Publisher) {
				continue
			}

			key := makeDedupKey(app)
			if seen[key] {
				continue
			}
			seen[key] = true
			apps = append(apps, app)
		}
	}

	return apps
}

func readAppEntry(key registry.Key, path, source string) (InstalledApp, error) {
	k, err := registry.OpenKey(key, path, registry.QUERY_VALUE)
	if err != nil {
		return InstalledApp{}, err
	}
	defer k.Close()

	readStr := func(name string) string {
		s, _, _ := k.GetStringValue(name)
		return strings.TrimSpace(s)
	}
	readUint := func(name string) uint64 {
		u, _, _ := k.GetIntegerValue(name)
		return u
	}

	var lastMod string
	if stat, err := os.Stat(path); err == nil {
		lastMod = stat.ModTime().Format(time.RFC3339)
	}

	app := InstalledApp{
		Name:            readStr("DisplayName"),
		Version:         readStr("DisplayVersion"),
		Publisher:       readStr("Publisher"),
		InstallLocation: readStr("InstallLocation"),
		InstallDate:     normalizeInstallDate(readStr("InstallDate")),
		UninstallString: readStr("UninstallString"),
		SizeKB:          readUint("EstimatedSize"),
		IsSystem:        readUint("SystemComponent") == 1,
		Source:          source,
		LastModified:    lastMod,
	}

	app.InstallLocation = validateInstallPath(app.InstallLocation)
	app.InstallSource = detectInstallSource(app.UninstallString)
	app.RiskScore = calculateRiskScore(app)

	if app.InstallLocation != "" {
		app.ActualSizeKB = calculateDirSizeAsync(app.InstallLocation)
	}

	return app, nil
}

func normalizeInstallDate(dateStr string) string {
	if len(dateStr) != 8 {
		return dateStr
	}
	year, err1 := strconv.Atoi(dateStr[0:4])
	month, err2 := strconv.Atoi(dateStr[4:6])
	day, err3 := strconv.Atoi(dateStr[6:8])
	if err1 != nil || err2 != nil || err3 != nil {
		return dateStr
	}
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
}

func makeDedupKey(app InstalledApp) string {
	name := strings.ToLower(strings.TrimSpace(app.Name))
	version := strings.TrimSpace(app.Version)
	publisher := strings.TrimSpace(app.Publisher)

	if version == "" {
		version = "unknown"
	}
	if publisher == "" {
		publisher = "unknown"
	}

	return fmt.Sprintf("%s|%s|%s|%s", name, version, publisher, app.Source)
}

func isNoiseComponent(name, publisher string) bool {
	nameLower := strings.ToLower(name)
	publisherLower := strings.ToLower(publisher)

	noiseKeywords := []string{
		".net apphost pack", ".net runtime", ".net templates",
		".net workload", ".net sdk", "microsoft.net",
		"host fx resolver", "host -", "asp.net core",
		"manifest-", "targeting pack", "reference assemblies",
		"intellitrace", "diagnosticshub", "vs_", "vssdk",
		"clickonce", "bootstrapper", "filetracker",
		"visual c++", "crt.redist", "vcpp_crt",
		"windows sdk", "windows kit", "debuggers",
		"click-to-run", "office 16 click",
		"neutral", "x64", "x86", "arm64", "resource package",
		"shared framework", "appx package", "local feed",
	}

	if publisherLower == "microsoft corporation" {
		for _, kw := range noiseKeywords {
			if strings.Contains(nameLower, kw) {
				return true
			}
		}
	}

	systemKeywords := []string{
		"microsoft visual c++ redistributable",
	}
	for _, sk := range systemKeywords {
		if strings.Contains(nameLower, sk) {
			return false
		}
	}

	return false
}

func validateInstallPath(path string) string {
	if path == "" {
		return ""
	}
	if stat, err := os.Stat(path); err != nil || !stat.IsDir() {
		return ""
	}
	return path
}

func calculateRiskScore(app InstalledApp) int {
	score := 0
	nameLower := strings.ToLower(app.Name)
	locLower := strings.ToLower(app.InstallLocation)

	suspiciousPaths := []string{
		`appdata\local\temp`, `appdata\roaming`, `\users\public\`,
	}
	for _, p := range suspiciousPaths {
		if strings.Contains(locLower, p) {
			score += 25
			break
		}
	}

	if app.Publisher == "" && app.UninstallString == "" {
		score += 20
	}

	riskyNames := []string{"mimikatz", "psexec", "procdump", "bloodhound"}
	for _, rn := range riskyNames {
		if strings.Contains(nameLower, rn) {
			score += 40
			break
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

func detectInstallSource(uninstallStr string) string {
	if uninstallStr == "" {
		return "Unknown"
	}
	if strings.Contains(uninstallStr, "MsiExec") || strings.Contains(uninstallStr, ".msi") {
		return "MSI"
	}
	if strings.Contains(uninstallStr, "unins000.exe") {
		return "InnoSetup"
	}
	if strings.Contains(uninstallStr, "uninstall.exe") {
		return "NSIS/Custom"
	}
	return "EXE"
}

func calculateDirSizeAsync(path string) uint64 {
	if path == "" {
		return 0
	}

	resultChan := make(chan uint64, 1)

	go func() {
		var size int64
		err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				size += info.Size()
			}
			return nil
		})

		if err == nil && size > 0 {
			resultChan <- uint64(size / 1024)
		} else {
			resultChan <- 0
		}
	}()

	select {
	case size := <-resultChan:
		return size
	case <-time.After(500 * time.Millisecond):
		return 0
	}
}
