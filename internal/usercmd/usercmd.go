package usercmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/hnrobert/lumgr/internal/hostfs"
	"github.com/hnrobert/lumgr/internal/logger"
	"github.com/hnrobert/lumgr/internal/usermgr"
)

type Runner struct {
	Timeout time.Duration
}

func New() *Runner {
	return &Runner{Timeout: 10 * time.Second}
}

func passwdPath() (string, error) { return hostfs.Path(hostfs.EtcPasswdRel) }
func shadowPath() (string, error) { return hostfs.Path(hostfs.EtcShadowRel) }
func groupPath() (string, error)  { return hostfs.Path(hostfs.EtcGroupRel) }

func daysSinceEpochUTC(t time.Time) string {
	return strconv.FormatInt(t.UTC().Unix()/86400, 10)
}

func firstFreeUID(pf *usermgr.PasswdFile, min int) int {
	used := map[int]struct{}{}
	for _, e := range pf.List() {
		used[e.UID] = struct{}{}
	}
	for uid := min; ; uid++ {
		if _, ok := used[uid]; !ok {
			return uid
		}
	}
}

func writePreservePerm(path string, data []byte) error {
	perm, err := hostfs.CopyFilePerms(path, path)
	if err != nil {
		// If stat fails, fall back to a conservative default.
		perm = 0600
	}
	logger.Info("Updating %s (%d bytes, perm %04o)", path, len(data), perm)
	return hostfs.WriteFileAtomic(path, data, perm)
}

func (r *Runner) AddUser(username, home, shell string, createHome bool) error {
	if username == "" {
		return errors.New("username is required")
	}
	if home == "" {
		home = filepath.Join("/home", username)
	}
	if shell == "" {
		shell = "/bin/bash"
	}

	pp, err := passwdPath()
	if err != nil {
		return err
	}
	sp, err := shadowPath()
	if err != nil {
		return err
	}
	gp, err := groupPath()
	if err != nil {
		return err
	}

	pf, err := usermgr.LoadPasswd(pp)
	if err != nil {
		return err
	}
	if pf.Find(username) != nil {
		return fmt.Errorf("user already exists: %s", username)
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return err
	}
	sh, err := usermgr.LoadShadow(sp)
	if err != nil {
		return err
	}

	// Find the next available UID
	uid := firstFreeUID(pf, 1000)

	// Create a primary group matching the username if missing.
	gid := -1
	if g := gr.Find(username); g != nil {
		gid = g.GID
	} else {
		// Try to use the same GID as UID for the group
		if gr.FindByGID(uid) == nil {
			// UID is available for GID too
			gid = uid
		} else {
			// UID is taken, find next available GID starting from 1000
			gid = gr.NextGID(1000)
		}

		_ = gr.Add(usermgr.GroupEntry{Name: username, Passwd: "x", GID: gid, Members: []string{}})
	}

	if err := pf.Add(usermgr.PasswdEntry{Name: username, Passwd: "x", UID: uid, GID: gid, Gecos: "", Home: home, Shell: shell}); err != nil {
		return err
	}
	// Start locked; SetPassword will populate the hash.
	_ = sh.Add(usermgr.ShadowEntry{Name: username, Hash: "!", LastChange: daysSinceEpochUTC(time.Now()), Min: "", Max: "", Warn: "", Inactive: "", Expire: "", Reserved: ""})

	// Persist edits. Order chosen to keep /etc/passwd last (some tooling reads passwd first).
	if err := writePreservePerm(gp, gr.Bytes()); err != nil {
		return err
	}
	if err := writePreservePerm(sp, sh.Bytes()); err != nil {
		return err
	}
	if err := writePreservePerm(pp, pf.Bytes()); err != nil {
		return err
	}

	logger.Info("Created user %s (uid=%d gid=%d home=%s shell=%s create_home=%v)", username, uid, gid, home, shell, createHome)

	if createHome {
		if err := os.MkdirAll(home, 0750); err != nil {
			return err
		}
		_ = os.Chown(home, uid, gid)
	}
	return nil
}

func (r *Runner) SetPassword(username, password string) error {
	if username == "" {
		return errors.New("username is required")
	}
	sp, err := shadowPath()
	if err != nil {
		return err
	}
	sh, err := usermgr.LoadShadow(sp)
	if err != nil {
		return err
	}
	se := sh.Find(username)
	if se == nil {
		return fmt.Errorf("user not found: %s", username)
	}
	cr := sha512_crypt.New()
	hash, err := cr.Generate([]byte(password), nil)
	if err != nil {
		return err
	}
	se.Hash = hash
	se.LastChange = daysSinceEpochUTC(time.Now())
	if err := writePreservePerm(sp, sh.Bytes()); err != nil {
		return err
	}
	logger.Info("Updated password hash in %s for user %s (hash_prefix=%s)", sp, username, hashPrefix(hash))
	return nil
}

func hashPrefix(h string) string {
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "$") {
		// Return algo prefix like "$6$" or "$y$".
		parts := strings.SplitN(h, "$", 4)
		if len(parts) >= 3 {
			return "$" + parts[1] + "$"
		}
	}
	if len(h) > 6 {
		return h[:6]
	}
	return h
}

func (r *Runner) DelUser(username string, removeHome bool) error {
	if username == "" {
		return errors.New("username is required")
	}
	pp, err := passwdPath()
	if err != nil {
		return err
	}
	sp, err := shadowPath()
	if err != nil {
		return err
	}
	gp, err := groupPath()
	if err != nil {
		return err
	}

	pf, err := usermgr.LoadPasswd(pp)
	if err != nil {
		return err
	}
	pe := pf.Find(username)
	if pe == nil {
		return fmt.Errorf("user not found: %s", username)
	}
	sh, err := usermgr.LoadShadow(sp)
	if err != nil {
		return err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return err
	}

	_ = pf.Delete(username)
	_ = sh.Delete(username)
	gr.RemoveMemberEverywhere(username)

	// Remove the user's primary group if it looks like a private group.
	if g := gr.Find(username); g != nil {
		used := false
		for _, u := range pf.List() {
			if u.GID == g.GID {
				used = true
				break
			}
		}
		if !used && len(g.Members) == 0 {
			_ = gr.Delete(username)
		}
	}

	if err := writePreservePerm(gp, gr.Bytes()); err != nil {
		return err
	}
	if err := writePreservePerm(sp, sh.Bytes()); err != nil {
		return err
	}
	if err := writePreservePerm(pp, pf.Bytes()); err != nil {
		return err
	}
	logger.Info("Deleted user %s (remove_home=%v)", username, removeHome)

	if removeHome {
		home := pe.Home
		// Safety: only remove within /home.
		if strings.HasPrefix(home, "/home/") && home != "/home" {
			if err := os.RemoveAll(home); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) AddUserToGroup(username, group string) error {
	if username == "" || group == "" {
		return errors.New("username and group are required")
	}
	gp, err := groupPath()
	if err != nil {
		return err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return err
	}
	if err := gr.AddMember(group, username); err != nil {
		return err
	}
	return writePreservePerm(gp, gr.Bytes())
}

func (r *Runner) UpdateUserGroups(username string, groups []string) error {
	if username == "" {
		return errors.New("username is required")
	}
	gp, err := groupPath()
	if err != nil {
		return err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return err
	}
	gr.SetUserMemberships(username, groups)
	return writePreservePerm(gp, gr.Bytes())
}

func (r *Runner) GetUserGroups(username string) ([]string, error) {
	gp, err := groupPath()
	if err != nil {
		return nil, err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range gr.List() {
		for _, m := range g.Members {
			if m == username {
				out = append(out, g.Name)
				break
			}
		}
	}
	return out, nil
}

func (r *Runner) ListGroups() ([]string, error) {
	gp, err := groupPath()
	if err != nil {
		return nil, err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range gr.List() {
		out = append(out, g.Name)
	}
	return out, nil
}

func (r *Runner) AddGroup(name string, gid int) error {
	if name == "" {
		return errors.New("group name is required")
	}
	gp, err := groupPath()
	if err != nil {
		return err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return err
	}
	if gid == 0 {
		gid = gr.NextGID(1000)
	}
	if err := gr.Add(usermgr.GroupEntry{Name: name, Passwd: "x", GID: gid, Members: []string{}}); err != nil {
		return err
	}
	return writePreservePerm(gp, gr.Bytes())
}

func (r *Runner) DelGroup(name string) error {
	if name == "" {
		return errors.New("group name is required")
	}
	gp, err := groupPath()
	if err != nil {
		return err
	}
	gr, err := usermgr.LoadGroup(gp)
	if err != nil {
		return err
	}
	if !gr.Delete(name) {
		return errors.New("group not found")
	}
	return writePreservePerm(gp, gr.Bytes())
}

func (r *Runner) RecursiveChmodHome(user string, mode os.FileMode, setuid, setgid, sticky bool) error {
	pp, err := passwdPath()
	if err != nil {
		return err
	}
	pf, err := usermgr.LoadPasswd(pp)
	if err != nil {
		return err
	}
	pe := pf.Find(user)
	if pe == nil {
		return fmt.Errorf("user not found: %s", user)
	}
	home := pe.Home
	if home == "" || home == "/" || home == "/root" {
		return errors.New("refusing to chmod root or empty home")
	}

	return filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".ssh" {
			return filepath.SkipDir
		}
		m := mode
		if info.IsDir() {
			if setgid {
				m |= os.ModeSetgid
			}
			if sticky {
				m |= os.ModeSticky
			}
		}
		if setuid {
			m |= os.ModeSetuid
		}
		if err := os.Chmod(path, m); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("chmod %s: %w", path, err)
		}
		return nil
	})
}
