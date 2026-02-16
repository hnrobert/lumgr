package resmon

import "time"

type Metrics struct {
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	CPUUser   float64 `json:"cpu_user" yaml:"cpu_user"`
	CPUSystem float64 `json:"cpu_system" yaml:"cpu_system"`
	CPUIdle   float64 `json:"cpu_idle" yaml:"cpu_idle"`
	CPUUsage  float64 `json:"cpu_usage" yaml:"cpu_usage"`

	MemTotal     uint64 `json:"mem_total" yaml:"mem_total"`
	MemUsed      uint64 `json:"mem_used" yaml:"mem_used"`
	MemAvailable uint64 `json:"mem_available" yaml:"mem_available"`

	DiskReadBytes  uint64 `json:"disk_read_bytes" yaml:"disk_read_bytes"`
	DiskWriteBytes uint64 `json:"disk_write_bytes" yaml:"disk_write_bytes"`

	NetworkRxBytes uint64 `json:"network_rx_bytes" yaml:"network_rx_bytes"`
	NetworkTxBytes uint64 `json:"network_tx_bytes" yaml:"network_tx_bytes"`
}

type UserResource struct {
	Username    string  `json:"username" yaml:"username"`
	CPU         float64 `json:"cpu_percent" yaml:"cpu_percent"`
	MemoryBytes uint64  `json:"memory_bytes" yaml:"memory_bytes"`
}

type Sample struct {
	Timestamp time.Time      `json:"timestamp" yaml:"timestamp"`
	Metrics   Metrics        `json:"metrics" yaml:"metrics"`
	UserStats []UserResource `json:"user_stats,omitempty" yaml:"user_stats,omitempty"`
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
