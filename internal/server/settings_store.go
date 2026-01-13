package server

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hnrobert/lumgr/internal/usermgr"
)

type UserSettings struct {
	Term     string
	Redirect string
	GitName  string
	GitEmail string
	SSHKeys  string
}

func lookupUser(username string) (*usermgr.PasswdEntry, error) {
	pw, err := usermgr.LoadPasswd("/etc/passwd")
	if err != nil {
		return nil, err
	}
	e := pw.Find(username)
	if e == nil {
		return nil, fmt.Errorf("user not found")
	}
	return e, nil
}

func LoadUserSettings(username string) (UserSettings, error) {
	e, err := lookupUser(username)
	if err != nil {
		return UserSettings{}, err
	}
	st := UserSettings{}

	akPath := filepath.Join(e.Home, ".ssh", "authorized_keys")
	if b, err := os.ReadFile(akPath); err == nil {
		st.SSHKeys = string(b)
	}

	gcPath := filepath.Join(e.Home, ".gitconfig")
	if b, err := os.ReadFile(gcPath); err == nil {
		name, email := parseGitUser(b)
		st.GitName = name
		st.GitEmail = email
	}

	profPath := filepath.Join(e.Home, ".profile")
	if b, err := os.ReadFile(profPath); err == nil {
		term, redirect := parseProfileBlock(b)
		st.Term = term
		st.Redirect = redirect
	}

	return st, nil
}

func SaveUserSettings(username string, st UserSettings) error {
	e, err := lookupUser(username)
	if err != nil {
		return err
	}

	sshDir := filepath.Join(e.Home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}
	_ = os.Chown(sshDir, e.UID, e.GID)

	akPath := filepath.Join(sshDir, "authorized_keys")
	ak := strings.TrimSpace(st.SSHKeys)
	if ak != "" {
		ak += "\n"
	}
	if err := os.WriteFile(akPath, []byte(ak), 0600); err != nil {
		return err
	}
	_ = os.Chown(akPath, e.UID, e.GID)

	gcPath := filepath.Join(e.Home, ".gitconfig")
	gcNew := updateGitUser(readFileOrEmpty(gcPath), st.GitName, st.GitEmail)
	if err := os.WriteFile(gcPath, gcNew, 0644); err != nil {
		return err
	}
	_ = os.Chown(gcPath, e.UID, e.GID)

	profPath := filepath.Join(e.Home, ".profile")
	profNew := updateProfileBlock(readFileOrEmpty(profPath), st.Term, st.Redirect)
	if err := os.WriteFile(profPath, profNew, 0644); err != nil {
		return err
	}
	_ = os.Chown(profPath, e.UID, e.GID)

	return nil
}

func readFileOrEmpty(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func parseGitUser(b []byte) (string, string) {
	s := bufio.NewScanner(bytes.NewReader(b))
	inUser := false
	var name, email string
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.Trim(line, "[]")
			inUser = strings.EqualFold(strings.TrimSpace(sec), "user")
			continue
		}
		if !inUser {
			continue
		}
		if strings.HasPrefix(line, "name") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				name = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "email") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				email = strings.TrimSpace(parts[1])
			}
		}
	}
	return name, email
}

func updateGitUser(orig []byte, name, email string) []byte {
	lines := strings.Split(string(orig), "\n")
	var out []string
	seenUser := false
	inUser := false
	setName := false
	setEmail := false

	flushUserKV := func() {
		if !inUser {
			return
		}
		if !setName && strings.TrimSpace(name) != "" {
			out = append(out, "\tname = "+strings.TrimSpace(name))
		}
		if !setEmail && strings.TrimSpace(email) != "" {
			out = append(out, "\temail = "+strings.TrimSpace(email))
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			flushUserKV()
			sec := strings.Trim(trim, "[]")
			inUser = strings.EqualFold(strings.TrimSpace(sec), "user")
			if inUser {
				seenUser = true
				setName, setEmail = false, false
			}
			out = append(out, line)
			continue
		}
		if inUser {
			k := strings.TrimSpace(strings.SplitN(trim, "=", 2)[0])
			if strings.EqualFold(k, "name") {
				if strings.TrimSpace(name) != "" {
					out = append(out, "\tname = "+strings.TrimSpace(name))
					setName = true
				}
				continue
			}
			if strings.EqualFold(k, "email") {
				if strings.TrimSpace(email) != "" {
					out = append(out, "\temail = "+strings.TrimSpace(email))
					setEmail = true
				}
				continue
			}
		}
		out = append(out, line)
	}
	flushUserKV()

	if !seenUser && (strings.TrimSpace(name) != "" || strings.TrimSpace(email) != "") {
		out = append(out, "", "[user]")
		if strings.TrimSpace(name) != "" {
			out = append(out, "\tname = "+strings.TrimSpace(name))
		}
		if strings.TrimSpace(email) != "" {
			out = append(out, "\temail = "+strings.TrimSpace(email))
		}
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

const (
	profileBegin = "# lumgr begin"
	profileEnd   = "# lumgr end"
)

func parseProfileBlock(b []byte) (term, redirect string) {
	lines := strings.Split(string(b), "\n")
	in := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == profileBegin {
			in = true
			continue
		}
		if trim == profileEnd {
			break
		}
		if !in {
			continue
		}
		if strings.HasPrefix(trim, "export TERM=") {
			term = strings.TrimPrefix(trim, "export TERM=")
		}
		if strings.HasPrefix(trim, "cd ") {
			redirect = strings.TrimSpace(strings.TrimPrefix(trim, "cd "))
		}
	}
	return term, redirect
}

func updateProfileBlock(orig []byte, term, redirect string) []byte {
	lines := strings.Split(string(orig), "\n")
	var out []string
	in := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == profileBegin {
			in = true
			continue
		}
		if trim == profileEnd {
			in = false
			continue
		}
		if in {
			continue
		}
		out = append(out, line)
	}

	block := []string{profileBegin}
	if strings.TrimSpace(term) != "" {
		block = append(block, "export TERM="+strings.TrimSpace(term))
	}
	if strings.TrimSpace(redirect) != "" {
		block = append(block, "cd "+strings.TrimSpace(redirect))
	}
	block = append(block, profileEnd)

	if len(block) > 2 {
		out = append(out, "")
		out = append(out, block...)
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}
