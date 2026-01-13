package usercmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/hnrobert/lumgr/internal/hostfs"
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

func writePreservePerm(path string, data []byte) error {
	perm, err := hostfs.CopyFilePerms(path, path)
	if err != nil {
		// If stat fails, fall back to a conservative default.
		perm = 0600
	}
	return hostfs.WriteFileAtomic(path, data, perm)
}

func (r *Runner) run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s == "" {
			return err
		}
		return fmt.Errorf("%s %v: %s", name, args, s)
	}
	return nil
}

func (r *Runner) runWithStdin(stdin []byte, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if s == "" {
			return err
		}
		return fmt.Errorf("%s %v: %s", name, args, s)
	}
	return nil
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

	// Create a primary group matching the username if missing.
	gid := -1
	if g := gr.Find(username); g != nil {
		gid = g.GID
	} else {
		gid = gr.NextGID(1000)
		_ = gr.Add(usermgr.GroupEntry{Name: username, Passwd: "x", GID: gid, Members: []string{}})
	}
	uid := pf.NextUID(1000)

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
	return writePreservePerm(sp, sh.Bytes())
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
