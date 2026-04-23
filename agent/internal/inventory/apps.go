// internal/inventory/apps.go
package inventory

import (
	"fmt" // ← for makeDedupKey
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath" // ← for findMainExe
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// InstalledApp represents an application from Windows Uninstall registry
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
	IsSigned        bool   `json:"is_signed,omitempty"`
	FileHash        string `json:"file_hash,omitempty"`
	InstallSource   string `json:"install_source,omitempty"`
	RiskScore       int    `json:"risk_score,omitempty"`
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

			// 🔥 Skip noise components (SDK fragments, etc.)
			if isNoiseComponent(app.Name, app.Publisher) {
				continue
			}

			// 🔥 Robust deduplication with empty-field handling
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

	// Get file modification time for last_modified field
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

	// 🔐 Apply security enhancements
	app.InstallLocation = validateInstallPath(app.InstallLocation)
	app.InstallSource = detectInstallSource(app.UninstallString)

	// Get main exe for signing check
	mainExe := findMainExe(app.InstallLocation)
	app.IsSigned = isFileSigned(mainExe)

	app.RiskScore = calculateRiskScore(app)

	// 📊 Async directory size
	if app.InstallLocation != "" {
		app.ActualSizeKB = calculateDirSizeAsync(app.InstallLocation)
	}

	return app, nil
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

// === 🔐 SECURITY & FILTERING HELPERS ===

// makeDedupKey creates a robust deduplication key handling empty fields
func makeDedupKey(app InstalledApp) string {
	name := strings.ToLower(strings.TrimSpace(app.Name))
	version := strings.TrimSpace(app.Version)
	publisher := strings.TrimSpace(app.Publisher)

	// Fallbacks for missing fields
	if version == "" {
		version = "unknown"
	}
	if publisher == "" {
		publisher = "unknown"
	}

	// Include source to distinguish HKLM vs HKCU duplicates
	return fmt.Sprintf("%s|%s|%s|%s", name, version, publisher, app.Source)
}

// isNoiseComponent filters out Microsoft SDK/tooling fragments
// isNoiseComponent filters out Microsoft SDK/tooling fragments
func isNoiseComponent(name, publisher string) bool {
	nameLower := strings.ToLower(name)
	publisherLower := strings.ToLower(publisher)

	noiseKeywords := []string{
		// .NET runtime fragments
		".net apphost pack", ".net runtime", ".net templates",
		".net workload", ".net sdk", "microsoft.net",
		"host fx resolver", "host -", "asp.net core",

		// Visual Studio build components
		"manifest-", "targeting pack", "reference assemblies",
		"intellitrace", "diagnosticshub", "vs_", "vssdk",
		"clickonce", "bootstrapper", "filetracker",

		// C++ redistributables (keep user-facing ones)
		"visual c++", "crt.redist", "vcpp_crt",

		// Windows SDK / WDK fragments
		"windows sdk", "windows kit", "debuggers",

		// Office Click-to-Run internal components
		"click-to-run", "office 16 click",

		// Generic system/internal markers
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

	// Keep user-facing redistributables
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

// validateInstallPath checks if InstallLocation exists and is a directory
func validateInstallPath(path string) string {
	if path == "" {
		return ""
	}
	if stat, err := os.Stat(path); err != nil || !stat.IsDir() {
		return "" // Clear invalid path
	}
	return path
}

// calculateRiskScore assigns a simple risk score (0-100)
func calculateRiskScore(app InstalledApp) int {
	score := 0
	nameLower := strings.ToLower(app.Name)
	publisherLower := strings.ToLower(app.Publisher)

	// Unsigned + non-Microsoft = higher risk
	if !app.IsSigned && publisherLower != "microsoft corporation" && publisherLower != "" {
		score += 30
	}

	// Suspicious install locations
	suspiciousPaths := []string{
		`appdata\local\temp`, `appdata\roaming`, `\users\public\`,
	}
	locLower := strings.ToLower(app.InstallLocation)
	for _, p := range suspiciousPaths {
		if strings.Contains(locLower, p) {
			score += 25
			break
		}
	}

	// No publisher + no uninstall string = suspicious
	if app.Publisher == "" && app.UninstallString == "" {
		score += 20
	}

	// Known risky app names (example heuristic)
	riskyNames := []string{"mimikatz", "psexec", "procdump", "bloodhound"}
	for _, rn := range riskyNames {
		if strings.Contains(nameLower, rn) {
			score += 40
			break
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}
	return score
}

// detectInstallSource infers installer type from UninstallString
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

// findMainExe finds the primary executable in an install directory
func findMainExe(installDir string) string {
	entries, err := os.ReadDir(installDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
			// Skip uninstallers
			nameLower := strings.ToLower(e.Name())
			if strings.Contains(nameLower, "uninstall") || strings.Contains(nameLower, "setup") {
				continue
			}
			return filepath.Join(installDir, e.Name())
		}
	}
	return ""
}

// === 🔐 WINVERIFYTRUST IMPLEMENTATION (No external deps) ===

// WinTrust constants
const (
	WTD_UI_NONE                             = 2
	WTD_REVOKE_NONE                         = 0
	WTD_CHOICE_FILE                         = 1
	WTD_STATEACTION_VERIFY                  = 0x00000001
	WTD_STATEACTION_CLOSE                   = 0x00000002
	WTD_REVOCATION_CHECK_NONE               = 0x00000000
	WTD_SAFER_FLAG                          = 0x00000100
	WTD_HASH_ONLY_FLAG                      = 0x00000200
	WTD_USE_IE4_TRUST_FLAG                  = 0x00000001
	WTD_NO_IE4_CHAIN_FLAG                   = 0x00000002
	WTD_NO_POLICY_USAGE_FLAG                = 0x00000004
	WTD_REVOCATION_CHECK_END_CERT           = 0x00000010
	WTD_REVOCATION_CHECK_CHAIN              = 0x00000020
	WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000040
	WTD_SIGNED_APP_FLAG                     = 0x00000400
	WTD_VALIDITY_ONLY_FLAG                  = 0x00000800
	WTD_REVOCATION_CHECK_WHOLE_CHAIN        = 0x00000080
)

var (
	wintrustDLL                              = syscall.NewLazyDLL("wintrust.dll")
	crypt32DLL                               = syscall.NewLazyDLL("crypt32.dll")
	procWinVerifyTrust                       = wintrustDLL.NewProc("WinVerifyTrust")
	procCryptCATAdminAcquireContext2         = crypt32DLL.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminReleaseContext          = crypt32DLL.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle2 = crypt32DLL.NewProc("CryptCATAdminCalcHashFromFileHandle2")
)

// GUIDs for WinVerifyTrust
var (
	WINTRUST_ACTION_GENERIC_VERIFY_V2 = windows.GUID{
		Data1: 0xaac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}
)

// WinTrust structures
type WinTrustData struct {
	StructSize                      uint32
	PolicyCallbackData              uintptr
	SIPClientData                   uintptr
	UIChoice                        uint32
	RevocationChecks                uint32
	UnionChoice                     uint32
	FileOrCatalogOrBlobOrSgnrOrCert unsafe.Pointer
	StateAction                     uint32
	StateData                       windows.Handle
	URLReference                    *uint16
	ProvFlags                       uint32
	UIContext                       uint32
	SignatureSettings               *WinTrustSignatureSettings
}

type WinTrustFileInfo struct {
	StructSize   uint32
	FilePath     *uint16
	File         windows.Handle
	KnownSubject *windows.GUID
}

type WinTrustSignatureSettings struct {
	StructSize    uint32
	Index         uint32
	Flags         uint32
	SecondarySigs uint32
	SigPolicyID   windows.GUID
}

// isFileSigned verifies code signature using WinVerifyTrust (Windows native)
func isFileSigned(filePath string) bool {
	if filePath == "" {
		return false
	}

	// Convert path to UTF16 pointer
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return false
	}

	// Prepare WinTrustFileInfo
	wtf := WinTrustFileInfo{
		StructSize: uint32(unsafe.Sizeof(WinTrustFileInfo{})),
		FilePath:   pathPtr,
	}

	// Prepare WinTrustData
	wtd := WinTrustData{
		StructSize:                      uint32(unsafe.Sizeof(WinTrustData{})),
		UIChoice:                        WTD_UI_NONE,
		RevocationChecks:                WTD_REVOCATION_CHECK_NONE,
		UnionChoice:                     WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&wtf),
		StateAction:                     WTD_STATEACTION_VERIFY,
		ProvFlags:                       WTD_SAFER_FLAG | WTD_HASH_ONLY_FLAG,
	}

	// Call WinVerifyTrust
	ret, _, _ := procWinVerifyTrust.Call(
		0, // HWND
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&wtd)),
	)

	// Clean up state
	wtd.StateAction = WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&wtd)),
	)

	// ERROR_SUCCESS (0) = signature valid
	return ret == 0
}

// calculateDirSizeAsync computes directory size in KB (non-blocking)
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
