package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hnrobert/lumgr/internal/auth"
	"github.com/hnrobert/lumgr/internal/config"
	"github.com/hnrobert/lumgr/internal/invite"
	"github.com/hnrobert/lumgr/internal/logger"
	"github.com/hnrobert/lumgr/internal/usermgr"
)

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// parseOSRelease parses /etc/os-release and returns a map of key-value pairs
func parseOSRelease() map[string]string {
	result := make(map[string]string)
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return result
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		value := strings.Trim(parts[1], `"`)
		result[key] = value
	}
	return result
}

// getUbuntuDesktopGroups returns the list of groups needed for Ubuntu desktop login
func getUbuntuDesktopGroups() []string {
	return []string{
		"adm",
		"dialout",
		"cdrom",
		"audio",
		"video",
		"plugdev",
		"input",
		"netdev",
		"lpadmin",
	}
}

// isUbuntuDesktop returns true if running on Ubuntu
func isUbuntuDesktop() bool {
	osInfo := parseOSRelease()
	return strings.ToLower(osInfo["ID"]) == "ubuntu"
}

// copyDefaultBashrc copies the default .bashrc template to a user's home directory
// For Ubuntu systems, it uses .bashrc.ubuntu.default if available
func copyDefaultBashrc(username, homeDir string) error {
	osInfo := parseOSRelease()
	isUbuntu := strings.ToLower(osInfo["ID"]) == "ubuntu"

	var templatePath string
	if isUbuntu {
		// Try Ubuntu-specific bashrc first
		ubuntuPath := "/usr/local/share/lumgrd/assets/.bashrc.ubuntu.default"
		if _, err := os.Stat(ubuntuPath); err == nil {
			templatePath = ubuntuPath
			logger.Info("Using Ubuntu-specific .bashrc template for user %s", username)
		} else {
			// Fallback to generic
			templatePath = "/usr/local/share/lumgrd/assets/.bashrc.default"
			logger.Info("Ubuntu detected but ubuntu-specific .bashrc not found, using default for user %s", username)
		}
	} else {
		templatePath = "/usr/local/share/lumgrd/assets/.bashrc.default"
		logger.Info("Using generic .bashrc template for user %s", username)
	}

	targetPath := filepath.Join(homeDir, ".bashrc")

	// Read template
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read .bashrc template: %w", err)
	}

	// Write to user's home
	if err := os.WriteFile(targetPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write .bashrc: %w", err)
	}

	// Get user's UID/GID for chown
	pw, err := usermgr.LoadPasswd("/etc/passwd")
	if err != nil {
		return fmt.Errorf("failed to load passwd: %w", err)
	}
	u := pw.Find(username)
	if u == nil {
		return fmt.Errorf("user not found: %s", username)
	}

	// Change ownership
	if err := os.Chown(targetPath, u.UID, u.GID); err != nil {
		return fmt.Errorf("failed to chown .bashrc: %w", err)
	}

	logger.Info("Copied .bashrc template to %s for user %s", targetPath, username)
	return nil
}

// setupUserShellConfig configures shell rc and profile files for a user
func setupUserShellConfig(username, shell string) error {
	pw, err := usermgr.LoadPasswd("/etc/passwd")
	if err != nil {
		return err
	}
	u := pw.Find(username)
	if u == nil {
		return fmt.Errorf("user not found: %s", username)
	}

	// Create .lumgrc if it doesn't exist
	lumgrcPath := filepath.Join(u.Home, ".lumgrc")
	if _, err := os.Stat(lumgrcPath); os.IsNotExist(err) {
		_ = os.WriteFile(lumgrcPath, []byte(""), 0644)
		_ = os.Chown(lumgrcPath, u.UID, u.GID)
	}

	// Get shell-specific rc path
	shellName := filepath.Base(shell)
	var rcPath, profilePath string

	switch shellName {
	case "bash":
		rcPath = filepath.Join(u.Home, ".bashrc")
		profilePath = filepath.Join(u.Home, ".bash_profile")
	case "zsh":
		rcPath = filepath.Join(u.Home, ".zshrc")
		profilePath = filepath.Join(u.Home, ".zprofile")
	case "sh":
		rcPath = filepath.Join(u.Home, ".shrc")
		profilePath = filepath.Join(u.Home, ".profile")
	case "ksh":
		rcPath = filepath.Join(u.Home, ".kshrc")
		profilePath = filepath.Join(u.Home, ".profile")
	case "fish":
		rcPath = filepath.Join(u.Home, ".config", "fish", "config.fish")
		// fish doesn't use profile files in the same way
	default:
		logger.Info("Unsupported shell %s for user %s, skipping rc/profile setup", shell, username)
		return nil
	}

	// Ensure rc file sources .lumgrc
	if rcPath != "" {
		ensureSourceLumgrc(rcPath, u.UID, u.GID)

		// Ensure profile sources rc file (except for fish)
		if profilePath != "" && shellName != "fish" {
			ensureProfileSourcesRc(profilePath, rcPath, u.UID, u.GID)
		}
	}

	logger.Info("Configured shell files for user %s (shell: %s)", username, shell)
	return nil
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	cfg, _ := a.cfg.Get()
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if usernameFrom(r) != "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		a.renderPage(w, "login", &ViewData{HideNav: true, RegMode: string(cfg.RegistrationMode)})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		a.renderPage(w, "login", &ViewData{HideNav: true, RegMode: string(cfg.RegistrationMode), Flash: "Username and password are required.", FlashKind: "err"})
		return
	}
	if err := auth.VerifyPassword(username, password); err != nil {
		logger.Info("Failed login attempt for user %s from %s", username, remoteIP(r))
		a.renderPage(w, "login", &ViewData{HideNav: true, RegMode: string(cfg.RegistrationMode), Flash: auth.HumanAuthError(err), FlashKind: "err"})
		return
	}
	admin, _ := auth.IsAdmin(username)
	tok, err := auth.SignHS256(a.secret, username, admin, 24*time.Hour)
	if err != nil {
		a.renderPage(w, "login", &ViewData{HideNav: true, RegMode: string(cfg.RegistrationMode), Flash: "Failed to create session.", FlashKind: "err"})
		return
	}
	logger.Info("User %s logged in from %s", username, remoteIP(r))
	a.issueCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username := usernameFrom(r)
	logger.Info("User %s logged out from %s", username, remoteIP(r))
	a.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if usernameFrom(r) != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	cfg, _ := a.cfg.Get()
	mode := cfg.RegistrationMode
	data := &ViewData{RegMode: string(mode)}
	data.AvailableShells = LoadAvailableShells()
	if mode == config.RegistrationClosed {
		data.Flash = "Registration is disabled by the administrator."
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if mode == config.RegistrationInvite {
		if code != "" {
			if _, err := a.invites.Validate(code); err != nil {
				data.Flash = humanInviteError(err)
				data.FlashKind = "err"
			} else {
				data.InviteCode = code
			}
		}
	}
	a.renderPage(w, "register", data)
}

func (a *App) handleRegisterComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if usernameFrom(r) != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	code := strings.TrimSpace(r.Form.Get("code"))
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	password2 := r.Form.Get("password2")

	cfg, _ := a.cfg.Get()
	mode := cfg.RegistrationMode
	data := &ViewData{InviteCode: code, RegMode: string(mode)}
	if mode == config.RegistrationClosed {
		data.Flash = "Registration is disabled by the administrator."
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}

	createHome := true
	var groups []string
	umask := ""

	switch mode {
	case config.RegistrationInvite:
		if code == "" {
			data.Flash = "Invite code is required."
			data.FlashKind = "err"
			a.renderPage(w, "register", data)
			return
		}
		inv, err := a.invites.Validate(code)
		if err != nil {
			data.Flash = humanInviteError(err)
			data.FlashKind = "err"
			a.renderPage(w, "register", data)
			return
		}
		createHome = inv.CreateHome
		groups = inv.Groups
		umask = inv.Umask
		data.InviteCode = code
	case config.RegistrationOpen:
		groups = cfg.DefaultGroups
	}
	if username == "" || password == "" {
		data.Flash = "Username and password are required."
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}
	if password != password2 {
		data.Flash = "Passwords do not match."
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}
	if !usermgr.ValidUsername(username) {
		data.Flash = "Invalid username. Use Ubuntu-style names: lowercase letters/digits/underscore/dash, start with a letter or underscore."
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}

	home := "/home/" + username
	shell := strings.TrimSpace(r.Form.Get("shell"))
	if shell == "" {
		shell = "/bin/bash"
	}
	if err := a.users.AddUser(username, home, shell, createHome); err != nil {
		data.Flash = err.Error()
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}
	if err := a.users.SetPassword(username, password); err != nil {
		data.Flash = err.Error()
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}
	if err := auth.VerifyPassword(username, password); err != nil {
		logger.Error("Registration password verification failed for %s from %s: %v", username, remoteIP(r), err)
		data.Flash = "Password update failed to verify. Check server logs for /etc/shadow update details."
		data.FlashKind = "err"
		a.renderPage(w, "register", data)
		return
	}

	for _, g := range groups {
		if g != "" {
			_ = a.users.AddUserToGroup(username, g)
		}
	}

	// Copy default .bashrc if home directory was created
	if createHome {
		if err := copyDefaultBashrc(username, home); err != nil {
			logger.Info("Warning: failed to copy .bashrc for user %s: %v", username, err)
		}
	}

	// Setup shell configuration files (rc and profile)
	if err := setupUserShellConfig(username, shell); err != nil {
		logger.Info("Warning: failed to setup shell config for user %s: %v", username, err)
	}

	if strings.TrimSpace(umask) != "" {
		if err := SaveUserUmask(username, umask); err != nil {
			logger.Warn("Warning: failed to apply umask for user %s: %v", username, err)
		} else {
			logger.Info("Applied umask %s for user %s", umask, username)
		}
	}

	if mode == config.RegistrationInvite {
		_, _ = a.invites.Consume(code, username, remoteIP(r))
		logger.Info("User %s registered via invite from %s (groups: %v)", username, remoteIP(r), groups)
	} else {
		logger.Info("User %s registered via open registration from %s (groups: %v)", username, remoteIP(r), groups)
	}

	// Auto-login after registration
	admin, _ := auth.IsAdmin(username)
	tok, err := auth.SignHS256(a.secret, username, admin, 24*time.Hour)
	if err == nil {
		a.issueCookie(w, tok)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleAdminInvites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := a.baseData(r)
	list, err := a.invites.List()
	if err != nil {
		data.Flash = err.Error()
		data.FlashKind = "err"
		a.renderPage(w, "admin_invites", data)
		return
	}
	for _, inv := range list {
		inv.UsedCount = len(inv.Uses)
		data.Invites = append(data.Invites, InviteRow{ID: inv.ID, UsedCount: inv.UsedCount, MaxUses: inv.MaxUses, ExpiresAt: inv.ExpiresAt, CreateHome: inv.CreateHome, Groups: inv.Groups, Umask: inv.Umask})
	}

	cfg, _ := a.cfg.Get()
	data.DefaultGroups = cfg.DefaultGroups
	allGroups, _ := a.users.ListGroups()
	gp, _ := usermgr.LoadGroup("/etc/group")

	// Split groups into featured and system
	var feat, other []string
	for _, g := range allGroups {
		gid := 0
		if gr := gp.Find(g); gr != nil {
			gid = gr.GID
		}
		isFeat := (gid >= 1000 && gid <= 65533) || g == "sudo" || g == "docker"
		if isFeat {
			feat = append(feat, g)
		} else {
			other = append(other, g)
		}
	}

	sort.Strings(feat)
	sort.Strings(other)
	data.FeaturedGroups = feat
	data.OtherGroups = other
	data.AllGroups = allGroups
	// Sort groups alphabetically
	sort.Strings(data.AllGroups)

	if r.URL.Query().Get("ok") == "1" {
		data.Flash = "Saved."
		data.FlashKind = "ok"
	}
	if r.URL.Query().Get("err") == "1" {
		data.Flash = "Request failed."
		data.FlashKind = "err"
	}
	a.renderPage(w, "admin_invites", data)
}

func (a *App) handleAdminRegistrationMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()

	// Update mode
	if mode := strings.TrimSpace(r.Form.Get("mode")); mode != "" {
		if err := a.cfg.SetRegistrationMode(config.RegistrationMode(mode)); err != nil {
			http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
			return
		}
	}

	// Update default groups
	if r.Form.Has("default_groups_submit") {
		groups := r.Form["groups"] // from multi-select
		if err := a.cfg.SetDefaultGroups(groups); err != nil {
			http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/admin/invites?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminInvitesCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	maxUsesText := strings.TrimSpace(r.Form.Get("max_uses"))
	expiresText := strings.TrimSpace(r.Form.Get("expires_at"))
	createHome := r.Form.Get("create_home") != "0"
	groups := r.Form["groups"]
	umask := strings.TrimSpace(r.Form.Get("umask"))
	if umask != "" {
		norm, err := NormalizeUmask(umask)
		if err != nil {
			http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
			return
		}
		umask = norm
	}

	maxUses := 0
	if maxUsesText != "" {
		if v, err := strconv.Atoi(maxUsesText); err == nil {
			maxUses = v
		}
	}
	var expiresAt time.Time
	if expiresText != "" {
		if t, err := time.Parse(time.RFC3339, expiresText); err == nil {
			expiresAt = t
		}
	}
	if _, err := a.invites.Create(usernameFrom(r), maxUses, expiresAt, createHome, groups, umask); err != nil {
		http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
		return
	}
	adminUser := usernameFrom(r)
	logger.Info("Admin %s created invite from %s (groups: %v, max_uses: %d, umask: %s)", adminUser, remoteIP(r), groups, maxUses, umask)
	http.Redirect(w, r, "/admin/invites?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminInvitesDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	inviteID := strings.TrimSpace(r.Form.Get("invite_id"))
	if inviteID == "" {
		http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
		return
	}
	if err := a.invites.Delete(inviteID); err != nil {
		http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
		return
	}
	adminUser := usernameFrom(r)
	logger.Info("Admin %s deleted invite %s from %s", adminUser, inviteID, remoteIP(r))
	http.Redirect(w, r, "/admin/invites?ok=1", http.StatusSeeOther)
}

func humanInviteError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, invite.ErrNotFound) {
		return "Invite code not found."
	}
	if errors.Is(err, invite.ErrExpired) {
		return "Invite code has expired."
	}
	if errors.Is(err, invite.ErrNoUsesLeft) {
		return "Invite code has no uses left."
	}
	return "Invalid invite code."
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r)
	username := usernameFrom(r)

	// Get OS information
	osInfo := parseOSRelease()
	data.OSName = osInfo["NAME"]
	data.OSVersion = osInfo["VERSION"]
	data.OSPrettyName = osInfo["PRETTY_NAME"]

	// Get hostname
	if hostname, err := os.ReadFile("/etc/hostname"); err == nil {
		data.Hostname = strings.TrimSpace(string(hostname))
	}

	// Get home directory size for current user
	if e, err := lookupUser(username); err == nil {
		data.HomeSize = getDirectorySize(e.Home)
	}

	// Admin stats
	if data.Admin {
		pw, _ := usermgr.LoadPasswd("/etc/passwd")
		if pw != nil {
			userList := pw.List()
			for _, u := range userList {
				if u.UID >= 1000 && u.UID <= 65533 {
					data.TotalUsers++
					if isUserAdmin(u.Name) {
						data.AdminUsers++
					}
				}
			}
		}
	}

	// Load configured Lumgr notice markdown (fallback to default if empty)
	if md, err := a.cfg.GetLumgrWhatEdits(); err == nil && md != "" {
		data.LumgrWhatEdits = md
	} else {
		data.LumgrWhatEdits = defaultNotice
	}
	data.LumgrWhatEditsHTML = RenderMarkdown(data.LumgrWhatEdits)

	a.renderPage(w, "dashboard", data)
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	// Remove the old combined "all" settings page. GET redirects to the Shell page.
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		http.Redirect(w, r, "/settings/shell", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// For compatibility accept POST to /settings and delegate to the saver.
	user := usernameFrom(r)
	// Use the shell page as redirect base for compatibility when section not provided.
	a.handleSettingsSave(w, r, user, "settings_shell", "/settings/shell")
}

func (a *App) handleSettingsShell(w http.ResponseWriter, r *http.Request) {
	user := usernameFrom(r)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		data := a.buildSettingsData(r)
		// single modify card only -> do not show global Save all
		data.ShowSaveAll = false
		a.applySettingsFlash(data, r.URL.Query())
		a.renderPage(w, "settings_shell", data)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.handleSettingsSave(w, r, user, "settings_shell", "/settings/shell")
}

func (a *App) handleSettingsSSH(w http.ResponseWriter, r *http.Request) {
	user := usernameFrom(r)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		data := a.buildSettingsData(r)
		// Page contains a key generation card (creates) — do not show global "Save all"
		data.ShowSaveAll = false
		a.applySettingsFlash(data, r.URL.Query())
		a.renderPage(w, "settings_ssh", data)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.handleSettingsSave(w, r, user, "settings_ssh", "/settings/ssh")
}

func (a *App) handleSettingsGit(w http.ResponseWriter, r *http.Request) {
	user := usernameFrom(r)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		data := a.buildSettingsData(r)
		// single modify card only -> do not show global Save all
		data.ShowSaveAll = false
		a.applySettingsFlash(data, r.URL.Query())
		a.renderPage(w, "settings_git", data)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.handleSettingsSave(w, r, user, "settings_git", "/settings/git")
}

func (a *App) handleSettingsFilesystem(w http.ResponseWriter, r *http.Request) {
	user := usernameFrom(r)
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		action := r.Form.Get("action") // "chmod", "umask", "all"
		var chmodErr error
		var umaskErr error

		if action == "chmod" || action == "all" {
			ur := r.Form.Get("ur") == "1"
			uw := r.Form.Get("uw") == "1"
			ux := r.Form.Get("ux") == "1"

			gr := r.Form.Get("gr") == "1"
			gw := r.Form.Get("gw") == "1"
			gx := r.Form.Get("gx") == "1"

			or := r.Form.Get("or") == "1"
			ow := r.Form.Get("ow") == "1"
			ox := r.Form.Get("ox") == "1"

			setuid := r.Form.Get("setuid") == "1"
			setgid := r.Form.Get("setgid") == "1"
			sticky := r.Form.Get("sticky") == "1"

			var m os.FileMode
			if ur {
				m |= 0400
			}
			if uw {
				m |= 0200
			}
			if ux {
				m |= 0100
			}
			if gr {
				m |= 0040
			}
			if gw {
				m |= 0020
			}
			if gx {
				m |= 0010
			}
			if or {
				m |= 0004
			}
			if ow {
				m |= 0002
			}
			if ox {
				m |= 0001
			}

			admin := isAdminFrom(r)
			if !admin {
				// Non-admin: allow setgid only.
				setuid = false
				sticky = false
			}

			if err := a.users.RecursiveChmodHome(user, m, setuid, setgid, sticky); err != nil {
				chmodErr = err
				logger.Error("RecursiveChmodHome failed for %s: %v", user, err)
			}
		}

		if action == "umask" || action == "all" {
			um := strings.TrimSpace(r.Form.Get("umask"))
			// Allow empty to clear
			if strings.TrimSpace(um) == "" {
				um = ""
			}
			if err := SaveUserUmask(user, um); err != nil {
				umaskErr = err
				logger.Warn("Failed to save umask for %s: %v", user, err)
			}
		}

		// Redirect with appropriate status/query
		if chmodErr != nil && umaskErr != nil {
			msg := url.QueryEscape(chmodErr.Error() + "; " + umaskErr.Error())
			http.Redirect(w, r, "/settings/filesystem?flash="+msg, http.StatusSeeOther)
			return
		}
		if chmodErr != nil {
			msg := url.QueryEscape(chmodErr.Error())
			http.Redirect(w, r, "/settings/filesystem?flash="+msg, http.StatusSeeOther)
			return
		}
		if umaskErr != nil {
			// Distinguish invalid format
			if _, e := NormalizeUmask(strings.TrimSpace(r.Form.Get("umask"))); e != nil {
				http.Redirect(w, r, "/settings/filesystem?umerr=invalid", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/settings/filesystem?umerr=1", http.StatusSeeOther)
			return
		}

		// Success
		http.Redirect(w, r, "/settings/filesystem?ok=1", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := a.buildSettingsData(r)
	// This page contains multiple modify-only cards -> enable global "Save all"
	data.ShowSaveAll = true
	// Only filesystem-related flashes apply here.
	if r.URL.Query().Get("umok") == "1" {
		data.Flash = "Umask saved."
		data.FlashKind = "ok"
	}
	if code := r.URL.Query().Get("umerr"); code != "" {
		data.FlashKind = "err"
		switch code {
		case "invalid":
			data.Flash = "Invalid umask. Use octal digits like 022."
		default:
			data.Flash = "Failed to save umask."
		}
	}
	if r.URL.Query().Get("ok") == "1" {
		data.Flash = "Saved."
		data.FlashKind = "ok"
	}
	if msg := r.URL.Query().Get("flash"); msg != "" {
		data.Flash = msg
		data.FlashKind = "err"
	}
	// Ensure these helpers still point to the correct endpoints
	data.PermFormAction = "/settings/chmod"
	data.PermUmaskFormAction = "/settings/umask"
	data.PermUmaskValue = data.Umask
	data.PermSubmitLabel = "Apply Recursive Chmod"
	_ = user
	a.renderPage(w, "settings_filesystem", data)
}

func (a *App) handleSettingsSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := a.buildSettingsData(r)
	// single modify card only -> do not show global Save all
	data.ShowSaveAll = false
	if r.URL.Query().Get("pwok") == "1" {
		data.Flash = "Password updated."
		data.FlashKind = "ok"
	}
	if code := r.URL.Query().Get("pwerr"); code != "" {
		data.FlashKind = "err"
		switch code {
		case "mismatch":
			data.Flash = "Passwords do not match."
		case "current":
			data.Flash = "Current password is incorrect."
		default:
			data.Flash = "Password update failed. Check server logs for /etc/shadow update details."
		}
	}
	a.renderPage(w, "settings_security", data)
}

func (a *App) buildSettingsData(r *http.Request) *ViewData {
	user := usernameFrom(r)
	data := a.baseData(r)
	st, _ := LoadUserSettings(user)
	data.Term = st.Term
	data.Redirect = st.Redirect
	data.Shell = st.Shell
	data.GitName = st.GitName
	data.GitEmail = st.GitEmail
	data.GitSigningKey = st.GitSigningKey
	data.SSHKeys = st.SSHKeys
	data.AvailableShells = LoadAvailableShells()

	if um, err := LoadUserUmask(user); err == nil {
		data.Umask = um
	}

	if e, err := lookupUser(user); err == nil {
		data.HomePerms = getHomeDirPerms(e.Home)
		data.SSHPrivateKeys = listSSHPrivateKeys(e.Home)
		data.GitSigningKey = toTildePath(e.Home, data.GitSigningKey)
		data.GitSigningPub = loadSigningPubKey(e.Home, data.GitSigningKey)
	}

	// permission helpers (filesystem pages)
	data.PermFormAction = "/settings/chmod"
	data.PermIncludeSpecial = true
	data.PermSpecialSetUIDEditable = data.Admin
	data.PermSpecialSetGIDEditable = true
	data.PermSpecialStickyEditable = data.Admin
	data.PermUmaskFormAction = "/settings/umask"
	data.PermUmaskValue = data.Umask
	data.PermSubmitLabel = "Apply Recursive Chmod"

	return data
}

func toTildePath(home, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	homeClean := filepath.Clean(home)
	pp := filepath.Clean(p)
	if pp == homeClean {
		return "~"
	}
	if strings.HasPrefix(pp, homeClean+string(os.PathSeparator)) {
		return "~" + string(os.PathSeparator) + strings.TrimPrefix(pp, homeClean+string(os.PathSeparator))
	}
	return p
}

func (a *App) applySettingsFlash(data *ViewData, q url.Values) {
	if q.Get("ok") == "1" {
		data.Flash = "Saved."
		data.FlashKind = "ok"
	}
	if q.Get("sshkeyok") == "1" {
		data.Flash = "SSH key generated."
		data.FlashKind = "ok"
	}
	if msg := q.Get("flash"); msg != "" {
		data.Flash = msg
		data.FlashKind = "err"
	}
}

func (a *App) handleSettingsSave(w http.ResponseWriter, r *http.Request, user, pageName, redirectBase string) {
	_ = r.ParseForm()
	section := strings.TrimSpace(r.Form.Get("section"))
	// Default: if section isn't specified, treat as saving all fields present.
	if section == "" {
		section = "all"
	}
	cur, _ := LoadUserSettings(user)
	st := cur

	// Resolve home for path validation/expansion.
	e, _ := lookupUser(user)

	switch section {
	case "shell":
		st.Shell = strings.TrimSpace(r.Form.Get("shell"))
		st.Term = strings.TrimSpace(r.Form.Get("term"))
		st.Redirect = strings.TrimSpace(r.Form.Get("redirect"))
	case "ssh":
		st.SSHKeys = r.Form.Get("ssh_keys")
	case "git":
		st.GitName = strings.TrimSpace(r.Form.Get("git_name"))
		st.GitEmail = strings.TrimSpace(r.Form.Get("git_email"))
		selected := strings.TrimSpace(r.Form.Get("git_signing_key"))
		other := strings.TrimSpace(r.Form.Get("git_signing_key_other"))
		key := selected
		if other != "" {
			key = other
		}
		if e != nil {
			abs, err := normalizeHomePath(e.Home, key)
			if err != nil {
				data := a.buildSettingsData(r)
				data.Flash = err.Error()
				data.FlashKind = "err"
				a.renderPage(w, pageName, data)
				return
			}
			st.GitSigningKey = abs
		}
	case "all":
		// Only overwrite fields that were present in the submitted form.
		has := func(k string) bool { _, ok := r.Form[k]; return ok }
		if has("shell") {
			st.Shell = strings.TrimSpace(r.Form.Get("shell"))
		}
		if has("term") {
			st.Term = strings.TrimSpace(r.Form.Get("term"))
		}
		if has("redirect") {
			st.Redirect = strings.TrimSpace(r.Form.Get("redirect"))
		}
		if has("git_name") {
			st.GitName = strings.TrimSpace(r.Form.Get("git_name"))
		}
		if has("git_email") {
			st.GitEmail = strings.TrimSpace(r.Form.Get("git_email"))
		}
		if has("ssh_keys") {
			st.SSHKeys = r.Form.Get("ssh_keys")
		}
		// Git signing key: update only if user submitted either the select or the other input.
		if has("git_signing_key") || has("git_signing_key_other") {
			selected := strings.TrimSpace(r.Form.Get("git_signing_key"))
			other := strings.TrimSpace(r.Form.Get("git_signing_key_other"))
			key := selected
			if other != "" {
				key = other
			}
			if e != nil {
				abs, err := normalizeHomePath(e.Home, key)
				if err != nil {
					data := a.buildSettingsData(r)
					data.Flash = err.Error()
					data.FlashKind = "err"
					a.renderPage(w, pageName, data)
					return
				}
				st.GitSigningKey = abs
			}
		}
	default:
		data := a.buildSettingsData(r)
		data.Flash = "Unknown settings section."
		data.FlashKind = "err"
		a.renderPage(w, pageName, data)
		return
	}

	if err := SaveUserSettings(user, st); err != nil {
		data := a.buildSettingsData(r)
		data.Flash = err.Error()
		data.FlashKind = "err"
		a.renderPage(w, pageName, data)
		return
	}
	logger.Info("User %s updated settings from %s (section: %s)", user, remoteIP(r), section)
	http.Redirect(w, r, redirectBase+"?ok=1", http.StatusSeeOther)
}

func listSSHPrivateKeys(home string) []string {
	sshDir := filepath.Join(home, ".ssh")
	ents, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	ignore := map[string]bool{
		"authorized_keys": true,
		"known_hosts":     true,
		"known_hosts.old": true,
		"config":          true,
		".DS_Store":       true,
	}
	var keys []string
	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if ignore[name] {
			continue
		}
		if strings.HasSuffix(name, ".pub") {
			continue
		}
		keys = append(keys, "~/.ssh/"+name)
	}
	sort.Strings(keys)
	return keys
}

func normalizeHomePath(home, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		p = filepath.Join(home, strings.TrimPrefix(p, "~"+string(os.PathSeparator)))
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(home, p)
	}
	clean := filepath.Clean(p)
	homeClean := filepath.Clean(home)
	if clean != homeClean && !strings.HasPrefix(clean, homeClean+string(os.PathSeparator)) {
		return "", fmt.Errorf("path must be under your home directory")
	}
	return clean, nil
}

func loadSigningPubKey(home, signingKey string) string {
	if strings.TrimSpace(signingKey) == "" {
		return ""
	}
	keyPath, err := normalizeHomePath(home, signingKey)
	if err != nil {
		return ""
	}
	pubPath := keyPath
	if !strings.HasSuffix(pubPath, ".pub") {
		pubPath = pubPath + ".pub"
	}
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (a *App) handleSettingsSSHKeygen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := usernameFrom(r)
	_ = r.ParseForm()
	keyType := strings.TrimSpace(r.Form.Get("key_type"))
	fileName := strings.TrimSpace(r.Form.Get("key_file"))
	comment := strings.TrimSpace(r.Form.Get("key_comment"))
	passphrase := r.Form.Get("key_passphrase")
	if comment == "" {
		comment = user
	}
	if keyType == "" {
		keyType = "rsa"
	}
	if fileName == "" {
		fileName = "id_" + keyType
	}
	validName := regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	if !validName.MatchString(fileName) {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("Invalid key filename."), http.StatusSeeOther)
		return
	}
	e, err := lookupUser(user)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("User not found."), http.StatusSeeOther)
		return
	}
	sshDir := filepath.Join(e.Home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("Failed to create ~/.ssh."), http.StatusSeeOther)
		return
	}
	_ = os.Chown(sshDir, e.UID, e.GID)
	keyPath := filepath.Join(sshDir, fileName)
	if _, err := os.Stat(keyPath); err == nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("Key file already exists."), http.StatusSeeOther)
		return
	}

	args := []string{"-t", keyType, "-f", keyPath, "-N", passphrase, "-C", comment}
	if keyType == "rsa" {
		args = append(args, "-b", "4096")
	}
	cmd := exec.Command("ssh-keygen", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("ssh-keygen failed for %s: %v (%s)", user, err, strings.TrimSpace(string(out)))
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("ssh-keygen failed."), http.StatusSeeOther)
		return
	}
	_ = os.Chown(keyPath, e.UID, e.GID)
	_ = os.Chown(keyPath+".pub", e.UID, e.GID)
	logger.Info("User %s generated ssh key (%s) from %s", user, keyType, remoteIP(r))
	http.Redirect(w, r, "/settings/ssh?sshkeyok=1", http.StatusSeeOther)
}

// POST /settings/ssh/key/delete
func (a *App) handleSettingsSSHKeyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := usernameFrom(r)
	_ = r.ParseForm()
	key := strings.TrimSpace(r.Form.Get("key"))
	if key == "" {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("missing key"), http.StatusSeeOther)
		return
	}
	e, err := lookupUser(user)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("user lookup failed"), http.StatusSeeOther)
		return
	}
	kp, err := normalizeHomePath(e.Home, key)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// remove private and public
	_ = os.Remove(kp)
	_ = os.Remove(kp + ".pub")
	logger.Info("User %s deleted SSH key %s", user, kp)
	http.Redirect(w, r, "/settings/ssh?ok=1", http.StatusSeeOther)
}

// POST /settings/ssh/key/passphrase
func (a *App) handleSettingsSSHKeyPassphrase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := usernameFrom(r)
	_ = r.ParseForm()
	key := strings.TrimSpace(r.Form.Get("key"))
	oldp := r.Form.Get("old_passphrase")
	newp := r.Form.Get("new_passphrase")
	newp2 := r.Form.Get("new_passphrase2")
	if key == "" {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("missing key"), http.StatusSeeOther)
		return
	}
	if newp != newp2 {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("new passphrases do not match"), http.StatusSeeOther)
		return
	}
	e, err := lookupUser(user)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("user lookup failed"), http.StatusSeeOther)
		return
	}
	kp, err := normalizeHomePath(e.Home, key)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// ssh-keygen -p -f <file> -P <old> -N <new>
	cmd := exec.Command("ssh-keygen", "-p", "-f", kp, "-P", oldp, "-N", newp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn("ssh-keygen -p failed for %s: %v (%s)", user, err, strings.TrimSpace(string(out)))
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("failed to change passphrase"), http.StatusSeeOther)
		return
	}
	// ensure permissions
	_ = os.Chmod(kp, 0600)
	logger.Info("User %s changed passphrase for %s", user, kp)
	http.Redirect(w, r, "/settings/ssh?ok=1", http.StatusSeeOther)
}

// GET /settings/ssh/key/export?key=~/.ssh/id_rsa
func (a *App) handleSettingsSSHKeyExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := usernameFrom(r)
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("missing key"), http.StatusSeeOther)
		return
	}
	e, err := lookupUser(user)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("user lookup failed"), http.StatusSeeOther)
		return
	}
	kp, err := normalizeHomePath(e.Home, key)
	if err != nil {
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	cmd := exec.Command("ssh-keygen", "-y", "-f", kp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn("ssh-keygen -y failed for %s: %v (%s)", user, err, strings.TrimSpace(string(out)))
		http.Redirect(w, r, "/settings/ssh?flash="+url.QueryEscape("failed to export public key"), http.StatusSeeOther)
		return
	}
	pub := strings.TrimSpace(string(out))
	fn := filepath.Base(kp) + ".pub"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fn+"\"")
	_, _ = w.Write([]byte(pub + "\n"))
}

func (a *App) handleSettingsPassword(w http.ResponseWriter, r *http.Request) {
	// Ensure LumgrWhatEdits is present for settings page GETs in case of redirects
	_ = a.cfg // referenced to ensure cfg is available
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := usernameFrom(r)
	_ = r.ParseForm()
	current := r.Form.Get("current_password")
	newPass := r.Form.Get("new_password")
	newPass2 := r.Form.Get("new_password2")
	if strings.TrimSpace(current) == "" || strings.TrimSpace(newPass) == "" {
		http.Redirect(w, r, "/settings/security?pwerr=1", http.StatusSeeOther)
		return
	}
	if newPass != newPass2 {
		http.Redirect(w, r, "/settings/security?pwerr=mismatch", http.StatusSeeOther)
		return
	}
	if err := auth.VerifyPassword(user, current); err != nil {
		logger.Warn("Password change failed (verify current) for %s from %s: %v", user, remoteIP(r), err)
		http.Redirect(w, r, "/settings/security?pwerr=current", http.StatusSeeOther)
		return
	}
	if err := a.users.SetPassword(user, newPass); err != nil {
		logger.Error("Password change failed (set) for %s: %v", user, err)
		http.Redirect(w, r, "/settings/security?pwerr=1", http.StatusSeeOther)
		return
	}
	if err := auth.VerifyPassword(user, newPass); err != nil {
		logger.Error("Password change verification failed for %s from %s: %v", user, remoteIP(r), err)
		http.Redirect(w, r, "/settings/security?pwerr=1", http.StatusSeeOther)
		return
	}
	logger.Info("User %s changed password from %s", user, remoteIP(r))
	http.Redirect(w, r, "/settings/security?pwok=1", http.StatusSeeOther)
}

func (a *App) handleSettingsChmod(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := usernameFrom(r)

	ur := r.Form.Get("ur") == "1"
	uw := r.Form.Get("uw") == "1"
	ux := r.Form.Get("ux") == "1"

	gr := r.Form.Get("gr") == "1"
	gw := r.Form.Get("gw") == "1"
	gx := r.Form.Get("gx") == "1"

	or := r.Form.Get("or") == "1"
	ow := r.Form.Get("ow") == "1"
	ox := r.Form.Get("ox") == "1"

	setuid := r.Form.Get("setuid") == "1"
	setgid := r.Form.Get("setgid") == "1"
	sticky := r.Form.Get("sticky") == "1"

	var m os.FileMode
	if ur {
		m |= 0400
	}
	if uw {
		m |= 0200
	}
	if ux {
		m |= 0100
	}
	if gr {
		m |= 0040
	}
	if gw {
		m |= 0020
	}
	if gx {
		m |= 0010
	}
	if or {
		m |= 0004
	}
	if ow {
		m |= 0002
	}
	if ox {
		m |= 0001
	}

	admin := isAdminFrom(r)
	if !admin {
		// Non-admin: allow setgid only.
		setuid = false
		sticky = false
	}

	if err := a.users.RecursiveChmodHome(username, m, setuid, setgid, sticky); err != nil {
		logger.Error("RecursiveChmodHome failed for %s: %v", username, err)
		msg := url.QueryEscape(err.Error())
		http.Redirect(w, r, "/settings/filesystem?flash="+msg, http.StatusSeeOther)
		return
	}

	// Calculate octal for logging
	var octalValue int
	if setuid {
		octalValue += 4000
	}
	if setgid {
		octalValue += 2000
	}
	if sticky {
		octalValue += 1000
	}
	octalValue += int(m & 0777)

	logger.Info("User %s updated own permissions from %s (mode: %04o)", username, remoteIP(r), octalValue)
	http.Redirect(w, r, "/settings/filesystem?ok=1", http.StatusSeeOther)
}

func (a *App) handleSettingsUmask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := usernameFrom(r)
	_ = r.ParseForm()
	um := strings.TrimSpace(r.Form.Get("umask"))
	// Allow empty to clear
	if strings.TrimSpace(um) == "" {
		um = ""
	}
	if err := SaveUserUmask(user, um); err != nil {
		logger.Warn("Failed to save umask for %s: %v", user, err)
		// Distinguish invalid format
		if _, e := NormalizeUmask(um); e != nil {
			http.Redirect(w, r, "/settings/filesystem?umerr=invalid", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/settings/filesystem?umerr=1", http.StatusSeeOther)
		return
	}
	logger.Info("User %s updated umask to %q from %s", user, um, remoteIP(r))
	http.Redirect(w, r, "/settings/filesystem?umok=1", http.StatusSeeOther)
}

func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := a.baseData(r)
	pw, err := usermgr.LoadPasswd("/etc/passwd")
	if err != nil {
		data.Flash = err.Error()
		data.FlashKind = "err"
		a.renderPage(w, "admin_users", data)
		return
	}
	allGroups, _ := a.users.ListGroups()
	gp, _ := usermgr.LoadGroup("/etc/group")

	var users, sysUsers []UserRow
	userList := pw.List()

	// Sort by UID first
	// (Assumes usermgr.List() returns unordered or file-ordered. Let's do a bubble sort or slices.Sort?
	//  Actually, usermgr.List() returns sorted by name or format. Let's sort simply here.)
	//  However, to perform sort we need imports "sort". I will add it to imports later if missing.
	//  Wait, handlers.go already imports sort? Not sure. Let's check context.
	//  If not, I might need to manage imports.

	for _, u := range userList {
		userGroups := []string{}
		if gp != nil {
			for _, g := range allGroups {
				ent := gp.Find(g)
				if ent != nil {
					for _, member := range ent.Members {
						if member == u.Name {
							userGroups = append(userGroups, g)
							break
						}
					}
				}
			}
		}

		row := UserRow{Name: u.Name, UID: u.UID, Home: u.Home, Groups: userGroups}
		if u.UID >= 1000 && u.UID <= 65533 {
			users = append(users, row)
		} else {
			sysUsers = append(sysUsers, row)
		}
	}

	// Sort both lists by UID
	sort.Slice(users, func(i, j int) bool { return users[i].UID < users[j].UID })
	sort.Slice(sysUsers, func(i, j int) bool { return sysUsers[i].UID < sysUsers[j].UID })

	data.Users = users
	data.SystemUsers = sysUsers

	allGroups2, _ := a.users.ListGroups()
	// Split groups into featured and system
	var feat, other []string
	for _, g := range allGroups2 {
		gid := 0
		if gr := gp.Find(g); gr != nil {
			gid = gr.GID
		}
		isFeat := (gid >= 1000 && gid <= 65533) || g == "sudo" || g == "docker"
		if isFeat {
			feat = append(feat, g)
		} else {
			other = append(other, g)
		}
	}
	sort.Strings(feat)
	sort.Strings(other)
	data.FeaturedGroups = feat
	data.OtherGroups = other
	data.AllGroups = allGroups2
	sort.Strings(data.AllGroups)
	data.AvailableShells = LoadAvailableShells()

	if r.URL.Query().Get("ok") == "1" {
		data.Flash = "Saved."
		data.FlashKind = "ok"
	}
	if r.URL.Query().Get("err") == "1" {
		data.Flash = "Request failed."
		data.FlashKind = "err"
	}
	a.renderPage(w, "admin_users", data)
}

func (a *App) handleAdminUsersCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	shell := strings.TrimSpace(r.Form.Get("shell"))
	createHome := r.Form.Get("create_home") != "0"
	groups := r.Form["groups"]
	umask := strings.TrimSpace(r.Form.Get("umask"))
	if umask != "" {
		norm, err := NormalizeUmask(umask)
		if err != nil {
			http.Error(w, "invalid umask", http.StatusBadRequest)
			return
		}
		umask = norm
	}

	if username == "" || password == "" {
		http.Redirect(w, r, "/admin/users?err=1", http.StatusSeeOther)
		return
	}
	home := "/home/" + username
	if shell == "" {
		shell = "/bin/bash"
	}
	if !usermgr.ValidUsername(username) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}

	if err := a.users.AddUser(username, home, shell, createHome); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.users.SetPassword(username, password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := auth.VerifyPassword(username, password); err != nil {
		logger.Error("Admin create-user password verification failed for %s from %s: %v", username, remoteIP(r), err)
		http.Error(w, "password update failed to verify; check server logs", http.StatusInternalServerError)
		return
	}
	for _, g := range groups {
		if g != "" {
			_ = a.users.AddUserToGroup(username, g)
		}
	}

	// Copy default .bashrc if home directory was created
	if createHome {
		if err := copyDefaultBashrc(username, home); err != nil {
			logger.Info("Warning: failed to copy .bashrc for user %s: %v", username, err)
		}
	}

	// Setup shell configuration files (rc and profile)
	if err := setupUserShellConfig(username, shell); err != nil {
		logger.Info("Warning: failed to setup shell config for user %s: %v", username, err)
	}
	if umask != "" {
		if err := SaveUserUmask(username, umask); err != nil {
			logger.Warn("Warning: failed to apply umask for new user %s: %v", username, err)
		}
	}

	adminUser := usernameFrom(r)
	logger.Info("Admin %s created user %s from %s (groups: %v, shell: %s, umask: %s)", adminUser, username, remoteIP(r), groups, shell, umask)
	http.Redirect(w, r, "/admin/users?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminUsersDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("username"))
	if username == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if username == usernameFrom(r) {
		http.Error(w, "cannot delete current user", http.StatusBadRequest)
		return
	}
	if err := a.users.DelUser(username, true); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	adminUser := usernameFrom(r)
	logger.Info("Admin %s deleted user %s from %s", adminUser, username, remoteIP(r))
	http.Redirect(w, r, "/admin/users?ok=1", http.StatusSeeOther)
}

// getHomeDirPerms reads the permissions of home directory
func getHomeDirPerms(homeDir string) HomePerms {
	var perms HomePerms

	info, err := os.Stat(homeDir)
	if err != nil {
		// If home doesn't exist, return empty/default permissions
		return perms
	}

	mode := info.Mode()
	perm := mode.Perm()

	// User permissions
	perms.UserR = perm&0400 != 0
	perms.UserW = perm&0200 != 0
	perms.UserX = perm&0100 != 0

	// Group permissions
	perms.GroupR = perm&0040 != 0
	perms.GroupW = perm&0020 != 0
	perms.GroupX = perm&0010 != 0

	// Other permissions
	perms.OtherR = perm&0004 != 0
	perms.OtherW = perm&0002 != 0
	perms.OtherX = perm&0001 != 0

	// Special bits
	perms.SetUID = mode&os.ModeSetuid != 0
	perms.SetGID = mode&os.ModeSetgid != 0
	perms.Sticky = mode&os.ModeSticky != 0

	// Calculate octal representation - use only the basic rwx bits (0777)
	var octalValue uint32
	if perms.SetUID {
		octalValue += 04000
	}
	if perms.SetGID {
		octalValue += 02000
	}
	if perms.Sticky {
		octalValue += 01000
	}
	// Extract only the permission bits, not the special bits
	basicPerms := uint32(perm) & 0777
	octalValue += basicPerms
	perms.Octal = fmt.Sprintf("%04o", octalValue)

	return perms
}

const defaultNotice = "\nlumgr updates these files in your home directory:\n\n" +
	"- `~/.ssh/authorized_keys`\n" +
	"- `~/.gitconfig` (user.name / user.email)\n" +
	"- `~/.lumgrc` (TERM + optional redirect + umask)\n" +
	"- `~/.bashrc` / `~/.zshrc` (sources ~/.lumgrc)\n\n" +
	"And these system files:\n" +
	"- `/etc/passwd` (default shell)\n" +
	"- `/etc/shadow` (password hash)\n\n" +
	"If you already manage these yourself, you can keep doing so.\n"

func (a *App) handleAdminUserEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}

	data := a.baseData(r)

	// Check if user exists
	pw, err := usermgr.LoadPasswd("/etc/passwd")
	if err != nil {
		data.Flash = "Failed to load users: " + err.Error()
		data.FlashKind = "err"
		a.renderPage(w, "admin_users", data)
		return
	}
	u := pw.Find(username)
	if u == nil {
		data.Flash = "User not found."
		data.FlashKind = "err"
		http.Redirect(w, r, "/admin/users?err=1", http.StatusSeeOther)
		return
	}

	groups, err := a.users.GetUserGroups(username)
	if err != nil {
		groups = []string{}
	}

	allGroups, err := a.users.ListGroups()
	if err != nil {
		data.Flash = "Failed to load groups: " + err.Error()
		data.FlashKind = "err"
	}
	gp, _ := usermgr.LoadGroup("/etc/group")

	um, _ := LoadUserUmask(username)
	data.EditUser = UserRow{Name: u.Name, UID: u.UID, Home: u.Home, Groups: groups, Umask: um}

	// Split groups
	var feat, other []string
	for _, g := range allGroups {
		gid := 0
		if gr := gp.Find(g); gr != nil {
			gid = gr.GID
		}

		isFeat := (gid >= 1000 && gid <= 65533) || g == "sudo" || g == "docker"
		if isFeat {
			feat = append(feat, g)
		} else {
			other = append(other, g)
		}
	}
	sort.Strings(feat)
	sort.Strings(other)
	data.FeaturedGroups = feat
	data.OtherGroups = other

	// Get current permissions from user home
	data.HomePerms = getHomeDirPerms(u.Home)

	// perms form helpers
	data.PermFormAction = "/admin/users/chmod"
	data.PermIncludeSpecial = true
	data.PermSpecialSetUIDEditable = true
	data.PermSpecialSetGIDEditable = true
	data.PermSpecialStickyEditable = true
	data.PermUmaskFormAction = "/admin/users/umask"
	data.PermUmaskValue = data.EditUser.Umask
	data.PermSubmitLabel = "Apply Recursive Chmod"

	a.renderPage(w, "admin_user_edit", data)
}

func (a *App) handleAdminLumgrSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		data := a.baseData(r)
		if r.URL.Query().Get("ok") == "1" {
			data.Flash = "Saved."
			data.FlashKind = "ok"
		}
		md, _ := a.cfg.GetLumgrWhatEdits()
		if md == "" {
			md = defaultNotice
		}
		data.LumgrWhatEdits = md
		data.LumgrWhatEditsHTML = RenderMarkdown(data.LumgrWhatEdits)
		a.renderPage(w, "admin_lumgr_settings", data)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	val := r.Form.Get("user_notice")
	if err := a.cfg.SetLumgrUserNotice(val); err != nil {
		data := a.baseData(r)
		data.Flash = "Failed to save: " + err.Error()
		data.FlashKind = "err"
		data.LumgrWhatEdits = val
		a.renderPage(w, "admin_lumgr_settings", data)
		return
	}
	logger.Info("Admin %s updated Lumgr settings", usernameFrom(r))
	http.Redirect(w, r, "/admin/lumgr_settings?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminUserUmask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("username"))
	umask := strings.TrimSpace(r.Form.Get("umask"))
	if username == "" {
		http.Redirect(w, r, "/admin/users?err=1", http.StatusSeeOther)
		return
	}
	if umask != "" {
		norm, err := NormalizeUmask(umask)
		if err != nil {
			http.Redirect(w, r, "/admin/users/edit?user="+url.QueryEscape(username)+"&err=1", http.StatusSeeOther)
			return
		}
		umask = norm
	}
	if err := SaveUserUmask(username, umask); err != nil {
		logger.Error("Admin failed to set umask for %s: %v", username, err)
		http.Redirect(w, r, "/admin/users/edit?user="+url.QueryEscape(username)+"&err=1", http.StatusSeeOther)
		return
	}
	logger.Info("Admin %s set umask for %s to %q", usernameFrom(r), username, umask)
	http.Redirect(w, r, "/admin/users/edit?user="+url.QueryEscape(username)+"&ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminUserChmod(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := r.Form.Get("username")

	ur := r.Form.Get("ur") == "1"
	uw := r.Form.Get("uw") == "1"
	ux := r.Form.Get("ux") == "1"

	gr := r.Form.Get("gr") == "1"
	gw := r.Form.Get("gw") == "1"
	gx := r.Form.Get("gx") == "1"

	or := r.Form.Get("or") == "1"
	ow := r.Form.Get("ow") == "1"
	ox := r.Form.Get("ox") == "1"

	setuid := r.Form.Get("setuid") == "1"
	setgid := r.Form.Get("setgid") == "1"
	sticky := r.Form.Get("sticky") == "1"

	var m os.FileMode
	if ur {
		m |= 0400
	}
	if uw {
		m |= 0200
	}
	if ux {
		m |= 0100
	}
	if gr {
		m |= 0040
	}
	if gw {
		m |= 0020
	}
	if gx {
		m |= 0010
	}
	if or {
		m |= 0004
	}
	if ow {
		m |= 0002
	}
	if ox {
		m |= 0001
	}

	if err := a.users.RecursiveChmodHome(username, m, setuid, setgid, sticky); err != nil {
		logger.Error("RecursiveChmodHome failed for %s: %v", username, err)
		msg := url.QueryEscape(err.Error())
		http.Redirect(w, r, "/admin/users/edit?user="+username+"&flash="+msg, http.StatusSeeOther)
		return
	}
	adminUser := usernameFrom(r)

	// Calculate octal for logging
	var octalValue int
	if setuid {
		octalValue += 4000
	}
	if setgid {
		octalValue += 2000
	}
	if sticky {
		octalValue += 1000
	}
	octalValue += int(m & 0777)

	logger.Info("Admin %s updated permissions for user %s from %s (mode: %04o)", adminUser, username, remoteIP(r), octalValue)
	http.Redirect(w, r, "/admin/users/edit?user="+username+"&ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminUserUpdateGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/users?err=1", http.StatusSeeOther)
		return
	}

	username := r.Form.Get("username")
	groups := r.Form["groups"] // get all checked values

	if username == "" {
		http.Redirect(w, r, "/admin/users?err=1", http.StatusSeeOther)
		return
	}

	if err := a.users.UpdateUserGroups(username, groups); err != nil {
		// In a real app, redirect back to edit with error
		http.Redirect(w, r, "/admin/users/edit?user="+username+"&err=1", http.StatusSeeOther)
		return
	}

	adminUser := usernameFrom(r)
	logger.Info("Admin %s updated groups for user %s from %s (groups: %v)", adminUser, username, remoteIP(r), groups)
	http.Redirect(w, r, "/admin/users?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := a.baseData(r)
	gp, err := usermgr.LoadGroup("/etc/group")
	if err != nil {
		data.Flash = err.Error()
		data.FlashKind = "err"
		a.renderPage(w, "admin_groups", data)
		return
	}

	var featuredRows []GroupRow
	var systemRows []GroupRow
	list := gp.List()
	// Sort by GID? User didn't specify, but alphabetical usually better or ID. Let's do GID.
	// usermgr.List() sorts by GID.

	for _, g := range list {
		m := strings.Join(g.Members, ", ")
		row := GroupRow{Name: g.Name, GID: g.GID, Members: m}

		// Featured: sudo, docker, or GID 1000-65533
		if g.Name == "sudo" || g.Name == "docker" || (g.GID >= 1000 && g.GID <= 65533) {
			featuredRows = append(featuredRows, row)
		} else {
			systemRows = append(systemRows, row)
		}
	}
	data.Groups = featuredRows
	data.SystemGroups = systemRows

	if r.URL.Query().Get("ok") == "1" {
		data.Flash = "Saved."
		data.FlashKind = "ok"
	}
	if r.URL.Query().Get("err") == "1" {
		data.Flash = "Request failed."
		data.FlashKind = "err"
	}
	a.renderPage(w, "admin_groups", data)
}

func (a *App) handleAdminGroupsCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.Form.Get("group"))
	gid := 0
	if v, err := strconv.Atoi(r.Form.Get("gid")); err == nil {
		gid = v
	}

	if err := a.users.AddGroup(name, gid); err != nil {
		http.Redirect(w, r, "/admin/groups?err=1", http.StatusSeeOther)
		return
	}
	adminUser := usernameFrom(r)
	logger.Info("Admin %s created group %s (gid: %d) from %s", adminUser, name, gid, remoteIP(r))
	http.Redirect(w, r, "/admin/groups?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminGroupsDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.Form.Get("group"))

	if err := a.users.DelGroup(name); err != nil {
		http.Redirect(w, r, "/admin/groups?err=1", http.StatusSeeOther)
		return
	}
	adminUser := usernameFrom(r)
	logger.Info("Admin %s deleted group %s from %s", adminUser, name, remoteIP(r))
	http.Redirect(w, r, "/admin/groups?ok=1", http.StatusSeeOther)
}

func getDirectorySize(path string) string {
	var size int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case size < KB:
		return fmt.Sprintf("%d B", size)
	case size < MB:
		return fmt.Sprintf("%.2f KB", float64(size)/KB)
	case size < GB:
		return fmt.Sprintf("%.2f MB", float64(size)/MB)
	default:
		return fmt.Sprintf("%.2f GB", float64(size)/GB)
	}
}

func isUserAdmin(username string) bool {
	gp, err := usermgr.LoadGroup("/etc/group")
	if err != nil {
		return false
	}
	sudo := gp.Find("sudo")
	if sudo != nil {
		for _, m := range sudo.Members {
			if m == username {
				return true
			}
		}
	}
	wheel := gp.Find("wheel")
	if wheel != nil {
		for _, m := range wheel.Members {
			if m == username {
				return true
			}
		}
	}
	return false
}

func (a *App) baseData(r *http.Request) *ViewData {
	user := usernameFrom(r)
	admin := isAdminFrom(r)
	cfg, _ := a.cfg.Get()
	data := &ViewData{Authed: user != "", Username: user, Admin: admin, RegMode: string(cfg.RegistrationMode)}
	if r.URL.Query().Get("ok") == "1" {
		data.Flash = "Saved."
		data.FlashKind = "ok"
	}
	if r.URL.Query().Get("err") == "1" {
		data.Flash = "Request failed."
		data.FlashKind = "err"
	}
	if f := r.URL.Query().Get("flash"); f != "" {
		data.Flash = f
		data.FlashKind = "err"
	}
	// logger.Info("baseData: isUbuntuDesktop=%v", isUbuntuDesktop())
	// Add Ubuntu desktop groups if running on Ubuntu
	if isUbuntuDesktop() {
		ubuntuGroups := getUbuntuDesktopGroups()
		data.UbuntuDesktopGroups = ubuntuGroups
		// logger.Info("baseData: UbuntuDesktopGroups=%v", ubuntuGroups)
	}
	return data
}

func (a *App) renderPage(w http.ResponseWriter, page string, data *ViewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// annotate current page for template-driven nav highlighting
	if data != nil {
		data.CurrentPage = page
	}
	t := a.pages[page]
	if t == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		logger.Error("renderPage template execution failed for %s: %v", page, err)
		// Show details for admins in the response body to ease debugging (safe for local admin use).
		if data != nil && data.Admin {
			http.Error(w, "Internal Server Error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
