package usermgr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hnrobert/lumgr/internal/hostfs"
)

var (
	ErrUserNotFound  = errors.New("user not found")
	ErrGroupNotFound = errors.New("group not found")
)

type Manager struct {
	PasswdPath string
	ShadowPath string
	GroupPath  string
}

func NewDefault() (*Manager, error) {
	passwd, err := hostfs.Path(hostfs.EtcPasswdRel)
	if err != nil {
		return nil, err
	}
	shadow, err := hostfs.Path(hostfs.EtcShadowRel)
	if err != nil {
		return nil, err
	}
	group, err := hostfs.Path(hostfs.EtcGroupRel)
	if err != nil {
		return nil, err
	}
	return &Manager{PasswdPath: passwd, ShadowPath: shadow, GroupPath: group}, nil
}

type CreateUserRequest struct {
	Username     string
	PasswordHash string // already hashed shadow string
	Home         string
	Shell        string
	AddToSudo    bool
	ExtraGroups  []string
	CreateHome   bool
}

func (m *Manager) LoadAll() (*PasswdFile, *ShadowFile, *GroupFile, error) {
	pw, err := LoadPasswd(m.PasswdPath)
	if err != nil {
		return nil, nil, nil, err
	}
	sh, err := LoadShadow(m.ShadowPath)
	if err != nil {
		return nil, nil, nil, err
	}
	gr, err := LoadGroup(m.GroupPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return pw, sh, gr, nil
}

func (m *Manager) CreateUser(req CreateUserRequest) error {
	if !validUsername(req.Username) {
		return fmt.Errorf("invalid username")
	}
	pw, sh, gr, err := m.LoadAll()
	if err != nil {
		return err
	}
	if pw.Find(req.Username) != nil || sh.Find(req.Username) != nil {
		return fmt.Errorf("user already exists")
	}
	// Primary group: create if missing.
	primary := gr.Find(req.Username)
	if primary == nil {
		gid := gr.NextGID(1000)
		if err := gr.Add(GroupEntry{Name: req.Username, Passwd: "x", GID: gid}); err != nil {
			return err
		}
		primary = gr.Find(req.Username)
	}
	uid := pw.NextUID(1000)
	home := req.Home
	if home == "" {
		home = filepath.Join("/home", req.Username)
	}
	shell := req.Shell
	if shell == "" {
		shell = "/bin/bash"
	}
	if err := pw.Add(PasswdEntry{Name: req.Username, Passwd: "x", UID: uid, GID: primary.GID, Gecos: "", Home: home, Shell: shell}); err != nil {
		return err
	}
	days := fmt.Sprintf("%d", time.Now().Unix()/86400)
	if err := sh.Add(ShadowEntry{
		Name:       req.Username,
		Hash:       req.PasswordHash,
		LastChange: days,
		Min:        "0",
		Max:        "99999",
		Warn:       "7",
		Inactive:   "",
		Expire:     "",
		Reserved:   "",
	}); err != nil {
		return err
	}
	for _, g := range req.ExtraGroups {
		if g == "" {
			continue
		}
		if err := gr.AddMember(g, req.Username); err != nil {
			return err
		}
	}
	// Add to sudo or wheel if present, else create sudo.
	if req.AddToSudo {
		if gr.Find("sudo") != nil {
			_ = gr.AddMember("sudo", req.Username)
		} else if gr.Find("wheel") != nil {
			_ = gr.AddMember("wheel", req.Username)
		} else {
			gid := gr.NextGID(1000)
			_ = gr.Add(GroupEntry{Name: "sudo", Passwd: "x", GID: gid})
			_ = gr.AddMember("sudo", req.Username)
		}
	}
	if req.CreateHome {
		abs, err := hostfs.Abs(home)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(abs, 0755); err != nil {
			return err
		}
		// Best effort chown is not possible without syscall on host; container is root
		// but it is still the host kernel, so Chown works. Use numeric UID/GID.
		_ = os.Chown(abs, uid, primary.GID)
	}
	// Persist files.
	if err := hostfs.WriteFileAtomic(m.PasswdPath, pw.Bytes(), 0644); err != nil {
		return err
	}
	if err := hostfs.WriteFileAtomic(m.ShadowPath, sh.Bytes(), 0600); err != nil {
		return err
	}
	if err := hostfs.WriteFileAtomic(m.GroupPath, gr.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

func (m *Manager) GetUserHome(username string) (string, error) {
	pw, err := LoadPasswd(m.PasswdPath)
	if err != nil {
		return "", err
	}
	pe := pw.Find(username)
	if pe == nil {
		return "", ErrUserNotFound
	}
	return pe.Home, nil
}

func (m *Manager) SetUserShell(username, shell string) error {
	if shell == "" || !strings.HasPrefix(shell, "/") {
		return fmt.Errorf("invalid shell")
	}
	pw, err := LoadPasswd(m.PasswdPath)
	if err != nil {
		return err
	}
	pe := pw.Find(username)
	if pe == nil {
		return ErrUserNotFound
	}
	pe.Shell = shell
	return hostfs.WriteFileAtomic(m.PasswdPath, pw.Bytes(), 0644)
}

func (m *Manager) DeleteUser(username string, removeHome bool) error {
	pw, sh, gr, err := m.LoadAll()
	if err != nil {
		return err
	}
	pe := pw.Find(username)
	if pe == nil {
		return ErrUserNotFound
	}
	pw.Delete(username)
	sh.Delete(username)
	gr.RemoveMemberEverywhere(username)
	// Optionally delete primary group if it matches username.
	_ = gr.Delete(username)
	if removeHome {
		abs, err := hostfs.Abs(pe.Home)
		if err == nil {
			_ = os.RemoveAll(abs)
		}
	}
	// Persist files.
	if err := hostfs.WriteFileAtomic(m.PasswdPath, pw.Bytes(), 0644); err != nil {
		return err
	}
	if err := hostfs.WriteFileAtomic(m.ShadowPath, sh.Bytes(), 0600); err != nil {
		return err
	}
	if err := hostfs.WriteFileAtomic(m.GroupPath, gr.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

func (m *Manager) IsAdmin(username string) (bool, error) {
	_, _, gr, err := m.LoadAll()
	if err != nil {
		return false, err
	}
	return isSudoGroupMember(gr, username), nil
}

func isSudoGroupMember(gr *GroupFile, username string) bool {
	for _, gname := range []string{"sudo", "wheel"} {
		g := gr.Find(gname)
		if g == nil {
			continue
		}
		for _, m := range g.Members {
			if m == username {
				return true
			}
		}
	}
	return false
}
