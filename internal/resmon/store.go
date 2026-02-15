package resmon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	mu      sync.RWMutex
	path    string
	samples []Sample
}

func DefaultPath() string {
	return filepath.Join("/lumgr_data", "resmon_history.json")
}

func NewStore(path string) *Store {
	if path == "" {
		path = DefaultPath()
	}
	return &Store{path: path}
}

func (s *Store) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0777); err != nil {
		return err
	}
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(s.path, []byte("[]\n"), 0666); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.samples = nil
			return nil
		}
		return err
	}
	if len(b) == 0 {
		s.samples = nil
		return nil
	}
	var arr []Sample
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	s.samples = arr
	return nil
}

func (s *Store) Append(sample Sample, retentionDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	if err := os.MkdirAll(filepath.Dir(s.path), 0777); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.samples, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0666); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
