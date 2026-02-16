package resmon

import "time"

type FSInfo struct {
	MountPoint string  `json:"mount_point"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	UsePercent float64 `json:"use_percent"`
}

type Metrics struct {
	Timestamp time.Time `json:"timestamp"`

	CPUUser   float64 `json:"cpu_user"`
	CPUSystem float64 `json:"cpu_system"`
	CPUIdle   float64 `json:"cpu_idle"`
	CPUUsage  float64 `json:"cpu_usage"`

	MemTotal     uint64 `json:"mem_total"`
	MemUsed      uint64 `json:"mem_used"`
	MemAvailable uint64 `json:"mem_available"`

	DiskReadBytes  uint64 `json:"disk_read_bytes"`
	DiskWriteBytes uint64 `json:"disk_write_bytes"`

	Filesystems []FSInfo `json:"filesystems"`

	NetworkRxBytes uint64 `json:"network_rx_bytes"`
	NetworkTxBytes uint64 `json:"network_tx_bytes"`
}

type UserResource struct {
	Username    string  `json:"username"`
	CPU         float64 `json:"cpu_percent"`
	MemoryBytes uint64  `json:"memory_bytes"`
}

type Sample struct {
	Timestamp time.Time      `json:"timestamp"`
	Metrics   Metrics        `json:"metrics"`
	UserStats []UserResource `json:"user_stats,omitempty"`
}

type Config struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
	RetentionDays   int  `json:"retention_days"`

	CollectCPU        bool `json:"collect_cpu"`
	CollectMemory     bool `json:"collect_memory"`
	CollectDiskIO     bool `json:"collect_disk_io"`
	CollectFilesystem bool `json:"collect_filesystem"`
	CollectNetwork    bool `json:"collect_network"`
	CollectUserStats  bool `json:"collect_user_stats"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		IntervalSeconds:   30,
		RetentionDays:     7,
		CollectCPU:        true,
		CollectMemory:     true,
		CollectDiskIO:     true,
		CollectFilesystem: false,
		CollectNetwork:    true,
		CollectUserStats:  true,
	}
}

func (c Config) IsZero() bool {
	return !c.Enabled &&
		c.IntervalSeconds == 0 &&
		c.RetentionDays == 0 &&
		!c.CollectCPU &&
		!c.CollectMemory &&
		!c.CollectDiskIO &&
		!c.CollectFilesystem &&
		!c.CollectNetwork &&
		!c.CollectUserStats
}

func (c Config) WithDefaults() Config {
	d := DefaultConfig()
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = d.IntervalSeconds
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = d.RetentionDays
	}
	return c
}
