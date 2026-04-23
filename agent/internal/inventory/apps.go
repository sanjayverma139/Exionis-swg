// internal/inventory/apps.go
package inventory

import (
	"golang.org/x/sys/windows/registry"
	"strconv"
	"strings"
	"time"
	"os"
)

// InstalledApp represents an application from Windows Uninstall registry
type InstalledApp struct {
	Name            string `json:"display_name"`
	Version         string `json:"display_version"`
	Publisher       string `json:"publisher"`
	InstallLocation string `json:"install_location,omitempty"`
	InstallDate     string `json:"install_date,omitempty"` // YYYYMMDD
	UninstallString string `json:"uninstall_string,omitempty"`
	SizeKB          uint64 `json:"estimated_size_kb,omitempty"`
	IsSystem        bool   `json:"is_system_component"`
	Source          string `json:"registry_source"` // HKLM/HKCU/WoW64
	LastModified    string `json:"last_modified,omitempty"`
}

// CollectInstalledApps scans Windows registry for installed applications
func CollectInstalledApps() []InstalledApp {
	var apps []InstalledApp
	seen := make(map[string]bool) // Deduplication key: name+version+publisher

	// Registry paths to scan
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

			// Deduplicate by name+version+publisher
			key := strings.ToLower(app.Name + "|" + app.Version + "|" + app.Publisher)
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

	// Get file modification time for last_modified field
	var lastMod string
	if stat, err := os.Stat(path); err == nil {
		lastMod = stat.ModTime().Format(time.RFC3339)
	}

	return InstalledApp{
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
	}, nil
}

// normalizeInstallDate converts registry YYYYMMDD to ISO format
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