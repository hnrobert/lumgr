package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
}

type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func DefaultPath() string {
	return filepath.Join("/var/lib/lumgr", "config.json")
}

func (s *Store) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = os.MkdirAll(filepath.Dir(s.path), 0700)
	_ = applyOwnership(filepath.Dir(s.path))

	if _, err := os.Stat(s.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = s.saveLocked(Config{UpdatedAt: time.Now().UTC(), RegistrationMode: defaultRegistration})
		}
	}
	_ = applyOwnership(s.path)
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
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	_ = applyOwnership(filepath.Dir(s.path))

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	p := s.path
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	_ = applyOwnership(tmp)
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	_ = applyOwnership(p)
	return nil
}

func applyOwnership(path string) error {
	uidText := os.Getenv("LUMGR_DATA_UID")
	if uidText == "" {
		return nil
	}
	uid, err := strconv.Atoi(uidText)
	if err != nil || uid < 0 {
		return nil
	}

	gidText := os.Getenv("LUMGR_DATA_GID")
	gid := -1
	if gidText != "" {
		g, err := strconv.Atoi(gidText)
		if err == nil && g >= 0 {
			gid = g
		}
	}
	if gid < 0 {
		g, ok := inferGIDFromPasswd(uid)
		if ok {
			gid = g
		}
	}
	if gid < 0 {
		return nil
	}
	_ = os.Chown(path, uid, gid)
	return nil
}

func inferGIDFromPasswd(uid int) (int, bool) {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil || len(b) == 0 {
		return 0, false
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		u, err := strconv.Atoi(parts[2])
		if err != nil || u != uid {
			continue
		}
		g, err := strconv.Atoi(parts[3])
		if err != nil || g < 0 {
			return 0, false
		}
		return g, true
	}
	return 0, false
}
