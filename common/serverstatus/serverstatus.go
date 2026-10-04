// Package serverstatus generate the server system status
package serverstatus

import (
	"errors"
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// GetSystemInfo get the system info of a given periodic
func GetSystemInfo() (Cpu float64, Mem float64, Disk float64, Uptime uint64, err error) {
	var errorMessages []string

	cpuPercent, err := cpu.Percent(0, false)
	// Check if cpuPercent is empty
	if len(cpuPercent) > 0 && err == nil {
		Cpu = cpuPercent[0]
	} else {
		Cpu = 0
		errorMessages = append(errorMessages, fmt.Sprintf("get cpu usage failed: %s", err))
	}

	memUsage, err := mem.VirtualMemory()
	if err != nil {
		errorMessages = append(errorMessages, fmt.Sprintf("get mem usage failed: %s", err))
	} else {
		Mem = memUsage.UsedPercent
	}

	diskUsage, err := disk.Usage("/")
	if err != nil {
		errorMessages = append(errorMessages, fmt.Sprintf("get disk usage failed: %s", err))
	} else {
		Disk = diskUsage.UsedPercent
	}

	uptime, err := host.Uptime()
	if err != nil {
		errorMessages = append(errorMessages, fmt.Sprintf("get uptime failed: %s", err))
	} else {
		Uptime = uptime
	}

	if len(errorMessages) > 0 {
		err = errors.New(strings.Join(errorMessages, "; "))
	}

	return Cpu, Mem, Disk, Uptime, err
}
