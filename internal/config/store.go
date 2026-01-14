package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type RegistrationMode string

const (
	RegistrationClosed RegistrationMode = "closed"
	RegistrationInvite RegistrationMode = "invite"
	RegistrationOpen   RegistrationMode = "open"

	defaultRegistration = RegistrationInvite
)

type Config struct {
	UpdatedAt        time.Time        `json:"updated_at"`
	RegistrationMode RegistrationMode `json:"registration_mode"`
	DefaultGroups    []string         `json:"default_groups"`
}

type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func DefaultPath() string {
	return filepath.Join("/lumgr_data", "config.json")
}

func (s *Store) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = os.MkdirAll(filepath.Dir(s.path), 0777)
	_ = applyOwnership(filepath.Dir(s.path), true)

	if _, err := os.Stat(s.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = s.saveLocked(Config{UpdatedAt: time.Now().UTC(), RegistrationMode: defaultRegistration})
		}
	}
	_ = applyOwnership(s.path, false)
	return nil
}

func (s *Store) Get() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.getLocked()
	if err != nil {
		return Config{}, err
	}
	if cfg.RegistrationMode == "" {
		cfg.RegistrationMode = defaultRegistration
	}
	return cfg, nil
}

func (s *Store) SetRegistrationMode(mode RegistrationMode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if mode != RegistrationClosed && mode != RegistrationInvite && mode != RegistrationOpen {
		return errors.New("invalid registration mode")
	}

	cfg, _ := s.getLocked()
	cfg.UpdatedAt = time.Now().UTC()
	cfg.RegistrationMode = mode
	return s.saveLocked(cfg)
}

func (s *Store) SetDefaultGroups(groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, _ := s.getLocked()
	cfg.DefaultGroups = groups
	cfg.UpdatedAt = time.Now().UTC()
	return s.saveLocked(cfg)
}

func (s *Store) getLocked() (Config, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{RegistrationMode: defaultRegistration}, nil
		}
		return Config{}, err
	}
	if len(b) == 0 {
		return Config{RegistrationMode: defaultRegistration}, nil
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.RegistrationMode == "" {
		cfg.RegistrationMode = defaultRegistration
	}
	return cfg, nil
}

func (s *Store) saveLocked(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0777); err != nil {
		return err
	}
	_ = applyOwnership(filepath.Dir(s.path), true)

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	p := s.path
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0666); err != nil {
		return err
	}
	_ = applyOwnership(tmp, false)
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	_ = applyOwnership(p, false)
	return nil
}

func applyOwnership(path string, isDir bool) error {
	mode := os.FileMode(0666)
	if isDir {
		mode = 0777
	}
	return os.Chmod(path, mode)
}
