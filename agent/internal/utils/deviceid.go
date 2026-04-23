// internal/utils/deviceid.go
package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"strings"
)

// GetDeviceID returns a unique, privacy-safe hardware fingerprint
// Combines Machine GUID + Disk Serial + SHA256 hash
func GetDeviceID() (string, error) {
	var components []string
	
	// 1. Machine GUID (stable across OS reinstalls)
	if guid, err := getMachineGUID(); err == nil && guid != "" {
		components = append(components, "guid:"+guid)
	}
	
	// 2. Disk serial (first physical disk)
	if serial, err := getDiskSerial(); err == nil && serial != "" {
		components = append(components, "disk:"+serial)
	}
	
	// 3. Fallback: hostname + username if no hardware IDs
	if len(components) == 0 {
		if hostname, err := os.Hostname(); err == nil {
			components = append(components, "host:"+hostname)
		}
	}
	
	if len(components) == 0 {
		return "", fmt.Errorf("could not generate device ID")
	}
	
	// Hash the combined components for privacy
	input := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(input))
	return "dev:" + hex.EncodeToString(hash[:16]), nil // 128-bit fingerprint
}

func getMachineGUID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, 
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	
	guid, _, err := k.GetStringValue("MachineGuid")
	return strings.ToLower(guid), err
}

func getDiskSerial() (string, error) {
	// Query WMI for disk serial - simplified via registry fallback
	// Full WMI query would use github.com/go-ole/go-ole
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Class\{4D36E967-E325-11CE-BFC1-08002BE10318}`,
		registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	
	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	
	for _, sub := range subkeys {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Control\Class\{4D36E967-E325-11CE-BFC1-08002BE10318}\`+sub,
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		serial, _, _ := sk.GetStringValue("SerialNumber")
		sk.Close()
		if serial != "" && !strings.Contains(strings.ToLower(serial), "unknown") {
			return strings.TrimSpace(serial), nil
		}
	}
	return "", fmt.Errorf("no disk serial found")
}