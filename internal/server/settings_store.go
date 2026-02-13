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
	Term          string
	Redirect      string
	Shell         string
	GitName       string
	GitEmail      string
	GitSigningKey string
	SSHKeys       string
}

// NormalizeUmask validates and normalizes umask input.
// Accepts formats like "22", "022", "0022" and returns a 3-digit string (e.g. "022").
func NormalizeUmask(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0")
	if s == "" {
		return "", fmt.Errorf("invalid umask")
	}
	if len(s) > 3 {
		// If someone pasted 4 digits like 0022, keep last 3.
		s = s[len(s)-3:]
	}
	if len(s) < 3 {
		s = strings.Repeat("0", 3-len(s)) + s
	}
	for _, ch := range s {
		if ch < '0' || ch > '7' {
			return "", fmt.Errorf("invalid umask")
		}
	}
	return s, nil
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
	st.Shell = e.Shell

	akPath := filepath.Join(e.Home, ".ssh", "authorized_keys")
	if b, err := os.ReadFile(akPath); err == nil {
		st.SSHKeys = string(b)
	}

	gcPath := filepath.Join(e.Home, ".gitconfig")
	if b, err := os.ReadFile(gcPath); err == nil {
		name, email, signingKey := parseGitUser(b)
		st.GitName = name
		st.GitEmail = email
		st.GitSigningKey = signingKey
	}

	lumgrcPath := filepath.Join(e.Home, ".lumgrc")
	if b, err := os.ReadFile(lumgrcPath); err == nil {
		term, redirect := parseLumgrc(b)
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

	// Update shell in /etc/passwd if changed
	if st.Shell != "" && st.Shell != e.Shell {
		pw, err := usermgr.LoadPasswd("/etc/passwd")
		if err == nil {
			user := pw.Find(username)
			if user != nil {
				user.Shell = st.Shell
				_ = os.WriteFile("/etc/passwd", pw.Bytes(), 0644)
			}
		}
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
	gcNew := updateGitUser(readFileOrEmpty(gcPath), st.GitName, st.GitEmail, st.GitSigningKey)
	if strings.TrimSpace(st.GitSigningKey) != "" {
		gcNew = updateGitGPGFormatSSH(gcNew)
	}
	if err := os.WriteFile(gcPath, gcNew, 0644); err != nil {
		return err
	}
	_ = os.Chown(gcPath, e.UID, e.GID)

	// Write ~/.lumgrc
	lumgrcPath := filepath.Join(e.Home, ".lumgrc")
	orig := readFileOrEmpty(lumgrcPath)
	_, _, um := parseLumgrcWithUmask(orig)
	lumgrcNew := updateLumgrc(orig, st.Term, st.Redirect, um)
	if err := os.WriteFile(lumgrcPath, lumgrcNew, 0644); err != nil {
		return err
	}
	_ = os.Chown(lumgrcPath, e.UID, e.GID)

	// Ensure shell rc sources ~/.lumgrc and profile sources rc
	if st.Shell != "" {
		rcPath := getShellRcPath(e.Home, st.Shell)
		if rcPath != "" {
			ensureSourceLumgrc(rcPath, e.UID, e.GID)

			// Ensure profile sources rc file
			profilePath := getShellProfilePath(e.Home, st.Shell)
			if profilePath != "" {
				ensureProfileSourcesRc(profilePath, rcPath, e.UID, e.GID)
			}
		}
	}

	return nil
}

func readFileOrEmpty(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func parseGitUser(b []byte) (string, string, string) {
	s := bufio.NewScanner(bytes.NewReader(b))
	inUser := false
	var name, email, signingKey string
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
		if strings.HasPrefix(line, "signingkey") {
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				signingKey = strings.TrimSpace(parts[1])
			}
		}
	}
	return name, email, signingKey
}

func updateGitUser(orig []byte, name, email, signingKey string) []byte {
	lines := strings.Split(string(orig), "\n")
	var out []string
	seenUser := false
	inUser := false
	setName := false
	setEmail := false
	setSigningKey := false

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
		if !setSigningKey && strings.TrimSpace(signingKey) != "" {
			out = append(out, "\tsigningkey = "+strings.TrimSpace(signingKey))
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
				setName, setEmail, setSigningKey = false, false, false
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
			if strings.EqualFold(k, "signingkey") {
				if strings.TrimSpace(signingKey) != "" {
					out = append(out, "\tsigningkey = "+strings.TrimSpace(signingKey))
					setSigningKey = true
				}
				continue
			}
		}
		out = append(out, line)
	}
	flushUserKV()

	if !seenUser && (strings.TrimSpace(name) != "" || strings.TrimSpace(email) != "" || strings.TrimSpace(signingKey) != "") {
		out = append(out, "", "[user]")
		if strings.TrimSpace(name) != "" {
			out = append(out, "\tname = "+strings.TrimSpace(name))
		}
		if strings.TrimSpace(email) != "" {
			out = append(out, "\temail = "+strings.TrimSpace(email))
		}
		if strings.TrimSpace(signingKey) != "" {
			out = append(out, "\tsigningkey = "+strings.TrimSpace(signingKey))
		}
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

func updateGitGPGFormatSSH(orig []byte) []byte {
	lines := strings.Split(string(orig), "\n")
	var out []string
	seenGpg := false
	inGpg := false
	setFormat := false

	flushGpgKV := func() {
		if !inGpg {
			return
		}
		if !setFormat {
			out = append(out, "\tformat = ssh")
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			flushGpgKV()
			sec := strings.Trim(trim, "[]")
			inGpg = strings.EqualFold(strings.TrimSpace(sec), "gpg")
			if inGpg {
				seenGpg = true
				setFormat = false
			}
			out = append(out, line)
			continue
		}
		if inGpg {
			k := strings.TrimSpace(strings.SplitN(trim, "=", 2)[0])
			if strings.EqualFold(k, "format") {
				out = append(out, "\tformat = ssh")
				setFormat = true
				continue
			}
		}
		out = append(out, line)
	}
	flushGpgKV()

	if !seenGpg {
		out = append(out, "", "[gpg]", "\tformat = ssh")
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

const (
	lumgrcBegin = "# lumgr begin"
	lumgrcEnd   = "# lumgr end"
)

func parseLumgrc(b []byte) (term, redirect string) {
	term, redirect, _ = parseLumgrcWithUmask(b)
	return term, redirect
}

func parseLumgrcWithUmask(b []byte) (term, redirect, umask string) {
	lines := strings.Split(string(b), "\n")
	in := false
	sawBlock := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == lumgrcBegin {
			in = true
			sawBlock = true
			continue
		}
		if trim == lumgrcEnd {
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
		if strings.HasPrefix(trim, "umask ") {
			umask = strings.TrimSpace(strings.TrimPrefix(trim, "umask "))
		}
	}

	// If the file doesn't contain a lumgr-managed block, treat the whole file as lumgr-managed.
	// This allows ~/.lumgrc to be a simple config file without begin/end markers.
	if !sawBlock {
		for _, line := range lines {
			trim := strings.TrimSpace(line)
			if trim == "" || strings.HasPrefix(trim, "#") {
				continue
			}
			if strings.HasPrefix(trim, "export TERM=") {
				term = strings.TrimPrefix(trim, "export TERM=")
				continue
			}
			if strings.HasPrefix(trim, "cd ") {
				redirect = strings.TrimSpace(strings.TrimPrefix(trim, "cd "))
				continue
			}
			if strings.HasPrefix(trim, "umask ") {
				umask = strings.TrimSpace(strings.TrimPrefix(trim, "umask "))
				continue
			}
		}
	}
	return term, redirect, umask
}

func updateLumgrc(orig []byte, term, redirect, umask string) []byte {
	lines := strings.Split(string(orig), "\n")
	var out []string
	in := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == lumgrcBegin {
			in = true
			continue
		}
		if trim == lumgrcEnd {
			in = false
			continue
		}
		if in {
			continue
		}
		out = append(out, line)
	}

	// If the file is effectively only lumgr-managed content (no other lines besides the managed block and whitespace),
	// rewrite it without begin/end markers.
	outside := strings.TrimSpace(strings.Join(out, "\n"))
	if outside == "" {
		var managed []string
		if strings.TrimSpace(term) != "" {
			managed = append(managed, "export TERM="+strings.TrimSpace(term))
		}
		if strings.TrimSpace(redirect) != "" {
			managed = append(managed, "cd "+strings.TrimSpace(redirect))
		}
		if strings.TrimSpace(umask) != "" {
			managed = append(managed, "umask "+strings.TrimSpace(umask))
		}

		res := strings.Join(managed, "\n")
		if res != "" && !strings.HasSuffix(res, "\n") {
			res += "\n"
		}
		return []byte(res)
	}

	block := []string{lumgrcBegin}
	if strings.TrimSpace(term) != "" {
		block = append(block, "export TERM="+strings.TrimSpace(term))
	}
	if strings.TrimSpace(redirect) != "" {
		block = append(block, "cd "+strings.TrimSpace(redirect))
	}
	if strings.TrimSpace(umask) != "" {
		block = append(block, "umask "+strings.TrimSpace(umask))
	}
	block = append(block, lumgrcEnd)

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

func LoadUserUmask(username string) (string, error) {
	e, err := lookupUser(username)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(e.Home, ".lumgrc"))
	if err != nil {
		return "", nil
	}
	_, _, um := parseLumgrcWithUmask(b)
	if um == "" {
		return "", nil
	}
	norm, err := NormalizeUmask(um)
	if err != nil {
		return "", nil
	}
	return norm, nil
}

// SaveUserUmask sets (or clears) the user's umask in ~/.lumgrc.
// If umask is empty, it removes the umask line from the lumgr-managed block.
func SaveUserUmask(username string, umask string) error {
	e, err := lookupUser(username)
	if err != nil {
		return err
	}
	lumgrcPath := filepath.Join(e.Home, ".lumgrc")
	orig := readFileOrEmpty(lumgrcPath)
	term, redirect, _ := parseLumgrcWithUmask(orig)
	if strings.TrimSpace(umask) != "" {
		norm, err := NormalizeUmask(umask)
		if err != nil {
			return err
		}
		umask = norm
	}
	newBytes := updateLumgrc(orig, term, redirect, umask)
	if err := os.WriteFile(lumgrcPath, newBytes, 0644); err != nil {
		return err
	}
	_ = os.Chown(lumgrcPath, e.UID, e.GID)
	return nil
}

func getShellRcPath(home, shell string) string {
	shellName := filepath.Base(shell)
	switch shellName {
	case "bash":
		return filepath.Join(home, ".bashrc")
	case "zsh":
		return filepath.Join(home, ".zshrc")
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish")
	case "sh":
		return filepath.Join(home, ".shrc")
	case "ksh":
		return filepath.Join(home, ".kshrc")
	default:
		return ""
	}
}

func getShellProfilePath(home, shell string) string {
	shellName := filepath.Base(shell)
	switch shellName {
	case "bash":
		return filepath.Join(home, ".bash_profile")
	case "zsh":
		return filepath.Join(home, ".zprofile")
	case "sh":
		return filepath.Join(home, ".profile")
	case "ksh":
		return filepath.Join(home, ".profile")
	default:
		return ""
	}
}

func ensureSourceLumgrc(rcPath string, uid, gid int) {
	sourceLine := "[ -f ~/.lumgrc ] && source ~/.lumgrc"
	comment1 := "# Linux User Manager: loads ~/.lumgrc (umask/TERM/cd, etc.)"
	comment2 := "# If you change your login shell, copy this block to the new shell rc (e.g. ~/.bashrc or ~/.zshrc) so these settings still apply."
	b := readFileOrEmpty(rcPath)

	// Normalize to a single lumgr-managed block in the rc file.
	// - Remove any existing lumgr block (even if it doesn't contain the correct line)
	// - Remove any loose occurrences of sourcing ~/.lumgrc
	lines := strings.Split(string(b), "\n")
	var out []string
	in := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == lumgrcBegin {
			in = true
			continue
		}
		if trim == lumgrcEnd {
			in = false
			continue
		}
		if in {
			continue
		}
		if strings.Contains(line, "source ~/.lumgrc") || strings.Contains(line, ". ~/.lumgrc") {
			continue
		}
		out = append(out, line)
	}

	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}

	// Create parent dir if needed
	dir := filepath.Dir(rcPath)
	if dir != "." {
		_ = os.MkdirAll(dir, 0755)
		_ = os.Chown(dir, uid, gid)
	}

	resLines := out
	if len(resLines) > 0 {
		resLines = append(resLines, "")
	}
	resLines = append(resLines, lumgrcBegin, comment1, comment2, sourceLine, lumgrcEnd)
	content := strings.Join(resLines, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	_ = os.WriteFile(rcPath, []byte(content), 0644)
	_ = os.Chown(rcPath, uid, gid)
}

func ensureProfileSourcesRc(profilePath, rcPath string, uid, gid int) {
	rcFilename := filepath.Base(rcPath)
	sourceLine := "[ -f ~/" + rcFilename + " ] && source ~/" + rcFilename

	b := readFileOrEmpty(profilePath)
	// Check if already sources the rc file
	if strings.Contains(string(b), "source ~/"+rcFilename) || strings.Contains(string(b), ". ~/"+rcFilename) {
		return
	}

	// Create parent dir if needed
	dir := filepath.Dir(profilePath)
	if dir != "." {
		_ = os.MkdirAll(dir, 0755)
		_ = os.Chown(dir, uid, gid)
	}

	content := string(b)
	if !strings.HasSuffix(content, "\n") && len(content) > 0 {
		content += "\n"
	}
	content += "\n" + sourceLine + "\n"
	_ = os.WriteFile(profilePath, []byte(content), 0644)
	_ = os.Chown(profilePath, uid, gid)
}

func LoadAvailableShells() []string {
	b, err := os.ReadFile("/etc/shells")
	if err != nil {
		return []string{"/bin/bash", "/bin/sh"}
	}
	var shells []string
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shells = append(shells, line)
	}
	return shells
}
