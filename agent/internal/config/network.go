// Package config handles Windows privilege escalation and network filtering config.
package config

import (
	"net"
	"sync"
)

// ============================================================================
// NETWORK FILTERING CONFIGURATION
// ============================================================================
var (
	internalRanges []*net.IPNet
	configMu       sync.RWMutex
)

// InitNetworkConfig initializes internal IP ranges from CIDR strings
func InitNetworkConfig(ranges []string) error {
	configMu.Lock()
	defer configMu.Unlock()
	
	internalRanges = make([]*net.IPNet, 0, len(ranges))
	for _, cidr := range ranges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		internalRanges = append(internalRanges, ipnet)
	}
	return nil
}

// IsInternalIP checks if an IP address falls within configured internal ranges
func IsInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	configMu.RLock()
	defer configMu.RUnlock()
	
	for _, ipnet := range internalRanges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// GetInternalRanges returns a copy of configured ranges (thread-safe)
func GetInternalRanges() []string {
	configMu.RLock()
	defer configMu.RUnlock()
	
	result := make([]string, len(internalRanges))
	for i, ipnet := range internalRanges {
		result[i] = ipnet.String()
	}
	return result
}

// DefaultInternalRanges returns standard RFC 1918 + loopback ranges
func DefaultInternalRanges() []string {
	return []string{
		"127.0.0.0/8",    // IPv4 loopback
		"::1/128",        // IPv6 loopback
		"10.0.0.0/8",     // RFC 1918 private
		"172.16.0.0/12",  // RFC 1918 private
		"192.168.0.0/16", // RFC 1918 private
		"169.254.0.0/16", // Link-local
	}
}