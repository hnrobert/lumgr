package resmon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
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
	if err := s.migrateLegacyLocked(); err != nil {
		return err
	}
	files, err := s.listDailyFilesLocked()
	if err != nil {
		return err
	}
	merged := make([]Sample, 0)
	for _, name := range files {
		p := filepath.Join(s.dir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if len(b) == 0 {
			continue
		}
		var arr []Sample
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		merged = append(merged, arr...)
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
	s.samples = append(s.samples, sample)
	s.pruneLocked(retentionDays)
	return s.saveLocked()
}

func (s *Store) pruneLocked(retentionDays int) {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	keep := s.samples[:0]
	for _, sm := range s.samples {
		if sm.Timestamp.IsZero() || sm.Timestamp.After(cutoff) {
			keep = append(keep, sm)
		}
	}
	s.samples = keep
}

func (s *Store) Prune(retentionDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(retentionDays)
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
	for date, arr := range byDate {
		path := filepath.Join(s.dir, date+".json")
		if err := writeJSONAtomic(path, arr); err != nil {
			return err
		}
	}
	existing, err := s.listDailyFilesLocked()
	if err != nil {
		return err
	}
	for _, name := range existing {
		date := strings.TrimSuffix(name, ".json")
		if _, ok := byDate[date]; ok {
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
	if !strings.HasSuffix(name, ".json") {
		return false
	}
	date := strings.TrimSuffix(name, ".json")
	if len(date) != len("2006-01-02") {
		return false
	}
	_, err := time.Parse("2006-01-02", date)
	return err == nil
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

func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) migrateLegacyLocked() error {
	if strings.TrimSpace(s.legacyPath) == "" {
		return nil
	}
	b, err := os.ReadFile(s.legacyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		_ = os.Remove(s.legacyPath)
		return nil
	}
	var arr []Sample
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	if len(arr) == 0 {
		_ = os.Remove(s.legacyPath)
		return nil
	}
	byDate := map[string][]Sample{}
	for _, sm := range arr {
		ts := sm.Timestamp.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		date := ts.Format("2006-01-02")
		byDate[date] = append(byDate[date], sm)
	}
	for date, items := range byDate {
		if err := writeJSONAtomic(filepath.Join(s.dir, date+".json"), items); err != nil {
			return err
		}
	}
	return os.Remove(s.legacyPath)
}
