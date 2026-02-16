package resmon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Store struct {
	mu         sync.RWMutex
	dir        string
	legacyPath string
	samples    []Sample
}

func DefaultPath() string {
	return filepath.Join("/lumgr_data", "resmon_history")
}

func NewStore(path string) *Store {
	dir, legacy := normalizeStorePath(path)
	return &Store{dir: dir, legacyPath: legacy}
}

func (s *Store) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0777); err != nil {
		return err
	}
	return nil
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0777); err != nil {
		return err
	}
	files, err := s.listDailyFilesLocked()
	if err != nil {
		return err
	}
	merged := make([]Sample, 0)
	for _, name := range files {
		p := filepath.Join(s.dir, name)
		f, err := os.Open(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}

		// detect by extension: .json (legacy) or .yaml/.yml (appended YAML docs)
		ext := strings.ToLower(filepath.Ext(name))
		if ext == ".json" {
			b, err := os.ReadFile(p)
			_ = f.Close()
			if err != nil {
				return err
			}
			if len(b) == 0 {
				continue
			}
			var arr []Sample

			if err := yaml.Unmarshal(b, &arr); err != nil {
				return err
			}

			merged = append(merged, arr...)
			continue
		}

		// parse YAML stream (multiple documents)
		d := yaml.NewDecoder(f)
		for {
			var sm Sample
			err := d.Decode(&sm)
			if err != nil {
				if errors.Is(err, io.EOF) {
					_ = f.Close()
					break
				}
				_ = f.Close()
				return err
			}
			merged = append(merged, sm)
		}
	}

	sort.Slice(merged, func(i, j int) bool {
		ti := merged[i].Timestamp
		tj := merged[j].Timestamp
		if ti.Equal(tj) {
			return i < j
		}
		return ti.Before(tj)
	})
	s.samples = merged
	return nil
}

func (s *Store) Append(sample Sample, retentionDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sample.Timestamp.IsZero() {
		sample.Timestamp = time.Now().UTC()
	} else {
		sample.Timestamp = sample.Timestamp.UTC()
	}
	if isEffectivelyEmptySample(sample) {
		return nil
	}
	// append to in-memory slice
	s.samples = append(s.samples, sample)

	// append to today's YAML file (append-mode to reduce IO)
	if err := s.appendSampleToDailyFileLocked(sample); err != nil {
		return err
	}

	// prune in-memory; only rewrite files when pruning actually removed samples
	if s.pruneLocked(retentionDays) {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) pruneLocked(retentionDays int) bool {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	before := len(s.samples)
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	keep := s.samples[:0]
	for _, sm := range s.samples {
		if sm.Timestamp.IsZero() || sm.Timestamp.After(cutoff) {
			keep = append(keep, sm)
		}
	}
	s.samples = keep
	return len(s.samples) != before
}

func (s *Store) Prune(retentionDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pruneLocked(retentionDays) {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) List(since time.Time) []Sample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if since.IsZero() {
		out := make([]Sample, len(s.samples))
		copy(out, s.samples)
		return out
	}
	out := make([]Sample, 0, len(s.samples))
	for _, sm := range s.samples {
		if sm.Timestamp.After(since) || sm.Timestamp.Equal(since) {
			out = append(out, sm)
		}
	}
	return out
}

func (s *Store) Latest() *Sample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.samples) == 0 {
		return nil
	}
	v := s.samples[len(s.samples)-1]
	return &v
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(s.dir, 0777); err != nil {
		return err
	}
	byDate := map[string][]Sample{}
	for _, sm := range s.samples {
		ts := sm.Timestamp.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		key := ts.Format("2006-01-02")
		byDate[key] = append(byDate[key], sm)
	}
	// write each date's samples as a YAML stream (atomic write)
	for date, arr := range byDate {
		path := filepath.Join(s.dir, date+".yaml")
		if err := writeYAMLAtomic(path, arr); err != nil {
			return err
		}
	}
	// remove legacy files (any daily files not present in byDate)
	existing, err := s.listDailyFilesLocked()
	if err != nil {
		return err
	}
	for _, name := range existing {
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		base = strings.TrimSuffix(base, ".json")
		if _, ok := byDate[base]; ok {
			continue
		}
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

func normalizeStorePath(path string) (dir, legacy string) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	path = filepath.Clean(path)
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return filepath.Join(filepath.Dir(path), "resmon_history"), path
	}
	return path, filepath.Join(filepath.Dir(path), "resmon_history.json")
}

func isDailyFileName(name string) bool {
	if strings.HasSuffix(strings.ToLower(name), ".json") || strings.HasSuffix(strings.ToLower(name), ".yaml") || strings.HasSuffix(strings.ToLower(name), ".yml") {
		base := name[:len(name)-len(filepath.Ext(name))]
		if len(base) != len("2006-01-02") {
			return false
		}
		_, err := time.Parse("2006-01-02", base)
		return err == nil
	}
	return false
}

func (s *Store) listDailyFilesLocked() ([]string, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	files := make([]string, 0, len(ents))
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if isDailyFileName(name) {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func appendSampleToDailyFile(path string, sample Sample) error {
	// open for append, create if missing
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	if _, err := w.WriteString(formatYAMLSample(sample)); err != nil {
		return err
	}
	return w.Flush()
}

func (s *Store) appendSampleToDailyFileLocked(sample Sample) error {
	path := filepath.Join(s.dir, sample.Timestamp.UTC().Format("2006-01-02")+".yaml")
	return appendSampleToDailyFile(path, sample)
}

func formatYAMLSample(s Sample) string {
	// manual YAML emitter to avoid quoting keys/values as requested
	// omit metrics.timestamp to avoid duplicate timestamp in persisted files
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "---\n")
	fmt.Fprintf(sb, "timestamp: %s\n", s.Timestamp.UTC().Format(time.RFC3339Nano))
	m := s.Metrics
	fmt.Fprintf(sb, "metrics:\n")
	fmt.Fprintf(sb, "  cpu_user: %v\n", m.CPUUser)
	fmt.Fprintf(sb, "  cpu_system: %v\n", m.CPUSystem)
	fmt.Fprintf(sb, "  cpu_idle: %v\n", m.CPUIdle)
	fmt.Fprintf(sb, "  cpu_usage: %v\n", m.CPUUsage)
	fmt.Fprintf(sb, "  mem_total: %d\n", m.MemTotal)
	fmt.Fprintf(sb, "  mem_used: %d\n", m.MemUsed)
	fmt.Fprintf(sb, "  mem_available: %d\n", m.MemAvailable)
	fmt.Fprintf(sb, "  disk_read_bytes: %d\n", m.DiskReadBytes)
	fmt.Fprintf(sb, "  disk_write_bytes: %d\n", m.DiskWriteBytes)
	fmt.Fprintf(sb, "  network_rx_bytes: %d\n", m.NetworkRxBytes)
	fmt.Fprintf(sb, "  network_tx_bytes: %d\n", m.NetworkTxBytes)

	if len(s.UserStats) == 0 {
		fmt.Fprintf(sb, "user_stats: []\n")
	} else {
		fmt.Fprintf(sb, "user_stats:\n")
		for _, u := range s.UserStats {
			fmt.Fprintf(sb, "  - username: %s\n", u.Username)
			fmt.Fprintf(sb, "    cpu_percent: %v\n", u.CPU)
			fmt.Fprintf(sb, "    memory_bytes: %d\n", u.MemoryBytes)
		}
	}
	fmt.Fprintf(sb, "\n")
	return sb.String()
}

func writeYAMLAtomic(path string, samples []Sample) error {
	b := &strings.Builder{}
	for _, sm := range samples {
		b.WriteString(formatYAMLSample(sm))
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func isEffectivelyEmptySample(s Sample) bool {
	m := s.Metrics
	metricsAllZero := m.CPUUser == 0 &&
		m.CPUSystem == 0 &&
		m.CPUIdle == 0 &&
		m.CPUUsage == 0 &&
		m.MemTotal == 0 &&
		m.MemUsed == 0 &&
		m.MemAvailable == 0 &&
		m.DiskReadBytes == 0 &&
		m.DiskWriteBytes == 0 &&
		m.NetworkRxBytes == 0 &&
		m.NetworkTxBytes == 0

	return metricsAllZero && len(s.UserStats) == 0
}
