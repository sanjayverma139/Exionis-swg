//go:build windows
// +build windows

package telemetry

import (
	"fmt"

	"github.com/shirou/gopsutil/v3/host"
)

func BuildBootID() string {
	bootUnix, err := host.BootTime()
	if err != nil || bootUnix == 0 {
		return "boot-unknown"
	}
	return fmt.Sprintf("boot-%d", bootUnix)
}
