// Package stats collects OS-level resource metrics from /proc and syscalls.
// It has no external dependencies — only the Go standard library.
package stats

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Snapshot holds a point-in-time reading of server resources.
type Snapshot struct {
	CPU        float64 // percent used 0–100
	MemTotal   uint64  // bytes
	MemUsed    uint64  // bytes
	MemFree    uint64  // bytes
	MemPercent float64 // 0–100
	DiskTotal  uint64  // bytes (root filesystem)
	DiskUsed   uint64  // bytes
	DiskFree   uint64  // bytes
	DiskPercent float64 // 0–100
	Uptime     time.Duration
}

// Collect samples all metrics. CPU is measured over a ~250 ms window.
func Collect() (*Snapshot, error) {
	cpu, err := cpuPercent(250 * time.Millisecond)
	if err != nil {
		cpu = 0 // non-fatal on non-Linux
	}

	mem, err := memInfo()
	if err != nil {
		return nil, fmt.Errorf("mem: %w", err)
	}

	disk, err := diskInfo("/")
	if err != nil {
		return nil, fmt.Errorf("disk: %w", err)
	}

	uptime, err := readUptime()
	if err != nil {
		uptime = 0
	}

	return &Snapshot{
		CPU:         cpu,
		MemTotal:    mem.total,
		MemUsed:     mem.used,
		MemFree:     mem.free,
		MemPercent:  pct(mem.used, mem.total),
		DiskTotal:   disk.total,
		DiskUsed:    disk.used,
		DiskFree:    disk.free,
		DiskPercent: pct(disk.used, disk.total),
		Uptime:      uptime,
	}, nil
}

// ── CPU ──────────────────────────────────────────────────────

type cpuStat struct{ total, idle uint64 }

func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// user nice system idle iowait irq softirq steal ...
		var vals [8]uint64
		for i := 1; i < len(fields) && i <= 8; i++ {
			vals[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
		}
		total := vals[0] + vals[1] + vals[2] + vals[3] + vals[4] + vals[5] + vals[6] + vals[7]
		idle := vals[3] + vals[4] // idle + iowait
		return cpuStat{total: total, idle: idle}, nil
	}
	return cpuStat{}, fmt.Errorf("/proc/stat: cpu line not found")
}

func cpuPercent(interval time.Duration) (float64, error) {
	s1, err := readCPUStat()
	if err != nil {
		return 0, err
	}
	time.Sleep(interval)
	s2, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	totalDelta := float64(s2.total - s1.total)
	idleDelta := float64(s2.idle - s1.idle)
	if totalDelta == 0 {
		return 0, nil
	}
	return (1 - idleDelta/totalDelta) * 100, nil
}

// ── Memory ───────────────────────────────────────────────────

type memStats struct{ total, free, used, available uint64 }

func memInfo() (memStats, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return memStats{}, err
	}
	defer f.Close()

	kv := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		valStr = strings.TrimSuffix(valStr, " kB")
		v, _ := strconv.ParseUint(valStr, 10, 64)
		kv[key] = v * 1024 // convert kB → bytes
	}

	total := kv["MemTotal"]
	available := kv["MemAvailable"]
	if available == 0 {
		available = kv["MemFree"] + kv["Buffers"] + kv["Cached"]
	}
	used := total - available
	return memStats{total: total, free: available, used: used, available: available}, nil
}

// ── Disk ─────────────────────────────────────────────────────

type diskStats struct{ total, used, free uint64 }

func diskInfo(path string) (diskStats, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return diskStats{}, err
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	used := total - (st.Bfree * uint64(st.Bsize))
	return diskStats{total: total, used: used, free: free}, nil
}

// ── Uptime ───────────────────────────────────────────────────

func readUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	sec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(sec * float64(time.Second)), nil
}

// ── Helpers ──────────────────────────────────────────────────

func pct(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// FmtBytes formats bytes as human-readable string (B/KB/MB/GB).
func FmtBytes(b uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/GB)
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/MB)
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/KB)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FmtUptime formats a duration as "Xd Xh Xm".
func FmtUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}
