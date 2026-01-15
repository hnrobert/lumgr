package invite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("invite not found")
	ErrExpired       = errors.New("invite expired")
	ErrNoUsesLeft    = errors.New("invite has no uses left")
	ErrInvalidInvite = errors.New("invalid invite")
)

type Invite struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	MaxUses    int       `json:"max_uses"`   // 0 means unlimited
	UsedCount  int       `json:"used_count"` // derived from Uses
	CreateHome bool      `json:"create_home"`
	Groups     []string  `json:"groups"`

	Uses []Use `json:"uses,omitempty"`
}

type Use struct {
	UsedAt   time.Time `json:"used_at"`
	UsedBy   string    `json:"used_by"`
	RemoteIP string    `json:"remote_ip,omitempty"`
}

type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func DefaultPath() string {
	return filepath.Join("/lumgr_data", "invites.json")
}

// Ensure creates the backing directory (and an empty file if missing).
// It also sets permissions to 0666/0777 so the host user can read/write the bind-mounted files.
func (s *Store) Ensure() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = s.ensureDirLocked()
	if _, err := os.Stat(s.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = s.saveLocked(state{})
		}
	}
	_ = s.applyOwnershipLocked(filepath.Dir(s.path), true)
	_ = s.applyOwnershipLocked(s.path, false)
	return nil
}

func (s *Store) List() ([]Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	return st.Invites, nil
}

func (s *Store) Create(createdBy string, maxUses int, expiresAt time.Time, createHome bool, groups []string) (Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxUses < 0 {
		return Invite{}, fmt.Errorf("maxUses must be >= 0")
	}
	id, err := NewUUIDv4()
	if err != nil {
		return Invite{}, err
	}
	inv := Invite{
		ID:         id,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  createdBy,
		ExpiresAt:  expiresAt.UTC(),
		MaxUses:    maxUses,
		CreateHome: createHome,
		Groups:     groups,
	}
	if expiresAt.IsZero() {
		inv.ExpiresAt = time.Time{}
	}

	st, err := s.loadLocked()
	if err != nil {
		return Invite{}, err
	}
	st.Invites = append([]Invite{inv}, st.Invites...)
	if err := s.saveLocked(st); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

func (s *Store) Validate(id string) (Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return Invite{}, err
	}
	idx := indexOf(st.Invites, id)
	if idx < 0 {
		return Invite{}, ErrNotFound
	}
	inv := st.Invites[idx]
	inv.UsedCount = len(inv.Uses)
	if err := validateInvite(inv); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

func (s *Store) Consume(id, usedBy, remoteIP string) (Invite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return Invite{}, err
	}
	idx := indexOf(st.Invites, id)
	if idx < 0 {
		return Invite{}, ErrNotFound
	}
	inv := st.Invites[idx]
	inv.UsedCount = len(inv.Uses)
	if err := validateInvite(inv); err != nil {
		return Invite{}, err
	}

	inv.Uses = append(inv.Uses, Use{UsedAt: time.Now().UTC(), UsedBy: usedBy, RemoteIP: remoteIP})
	inv.UsedCount = len(inv.Uses)
	st.Invites[idx] = inv
	if err := s.saveLocked(st); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

type state struct {
	Invites []Invite `json:"invites"`
}

func (s *Store) loadLocked() (state, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state{}, nil
		}
		return state{}, err
	}
	if len(b) == 0 {
		return state{}, nil
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return state{}, err
	}
	return st, nil
}

func (s *Store) saveLocked(st state) error {
	if err := s.ensureDirLocked(); err != nil {
		return err
	}
	_ = s.applyOwnershipLocked(filepath.Dir(s.path), true)
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0666); err != nil {
		return err
	}
	_ = s.applyOwnershipLocked(tmp, false)
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	_ = s.applyOwnershipLocked(s.path, false)
	return nil
}

func (s *Store) ensureDirLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0777); err != nil {
		return err
	}
	_ = s.applyOwnershipLocked(filepath.Dir(s.path), true)
	return nil
}

func (s *Store) applyOwnershipLocked(path string, isDir bool) error {
	// Ensure file is world-readable/writable so host user can manage it
	mode := os.FileMode(0666)
	if isDir {
		mode = 0777
	}
	return os.Chmod(path, mode)
}

func validateInvite(inv Invite) error {
	if inv.ID == "" {
		return ErrInvalidInvite
	}
	now := time.Now().UTC()
	if !inv.ExpiresAt.IsZero() && now.After(inv.ExpiresAt) {
		return ErrExpired
	}
	if inv.MaxUses > 0 && inv.UsedCount >= inv.MaxUses {
		return ErrNoUsesLeft
	}
	return nil
}

func indexOf(invites []Invite, id string) int {
	for i := range invites {
		if invites[i].ID == id {
			return i
		}
	}
	return -1
}

// Delete removes an invite by ID.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return err
	}

	idx := indexOf(st.Invites, id)
	if idx == -1 {
		return ErrNotFound
	}

	// Remove the invite
	st.Invites = append(st.Invites[:idx], st.Invites[idx+1:]...)

	return s.saveLocked(st)
}
