package server

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hnrobert/lumgr/internal/auth"
	"github.com/hnrobert/lumgr/internal/config"
	"github.com/hnrobert/lumgr/internal/invite"
	"github.com/hnrobert/lumgr/internal/usermgr"
)

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
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
		a.renderPage(w, "login", &ViewData{HideNav: true, RegMode: string(cfg.RegistrationMode), Flash: auth.HumanAuthError(err), FlashKind: "err"})
		return
	}
	admin, _ := auth.IsAdmin(username)
	tok, err := auth.SignHS256(a.secret, username, admin, 24*time.Hour)
	if err != nil {
		a.renderPage(w, "login", &ViewData{HideNav: true, RegMode: string(cfg.RegistrationMode), Flash: "Failed to create session.", FlashKind: "err"})
		return
	}
	a.issueCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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
	if mode == config.RegistrationInvite {
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
		data.InviteCode = code
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
	shell := "/bin/bash"
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
	if mode == config.RegistrationInvite {
		_, _ = a.invites.Consume(code, username, remoteIP(r))
	}

	http.Redirect(w, r, "/login?ok=1", http.StatusSeeOther)
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
		data.Invites = append(data.Invites, InviteRow{ID: inv.ID, UsedCount: inv.UsedCount, MaxUses: inv.MaxUses, ExpiresAt: inv.ExpiresAt, CreateHome: inv.CreateHome})
	}
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
	mode := strings.TrimSpace(r.Form.Get("mode"))
	if err := a.cfg.SetRegistrationMode(config.RegistrationMode(mode)); err != nil {
		http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
		return
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
	if _, err := a.invites.Create(usernameFrom(r), maxUses, expiresAt, createHome); err != nil {
		http.Redirect(w, r, "/admin/invites?err=1", http.StatusSeeOther)
		return
	}
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
	a.renderPage(w, "dashboard", a.baseData(r))
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	user := usernameFrom(r)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		data := a.baseData(r)
		st, _ := LoadUserSettings(user)
		data.Term = st.Term
		data.Redirect = st.Redirect
		data.GitName = st.GitName
		data.GitEmail = st.GitEmail
		data.SSHKeys = st.SSHKeys
		a.renderPage(w, "settings", data)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	st := UserSettings{
		Term:     strings.TrimSpace(r.Form.Get("term")),
		Redirect: strings.TrimSpace(r.Form.Get("redirect")),
		GitName:  strings.TrimSpace(r.Form.Get("git_name")),
		GitEmail: strings.TrimSpace(r.Form.Get("git_email")),
		SSHKeys:  r.Form.Get("ssh_keys"),
	}
	if err := SaveUserSettings(user, st); err != nil {
		data := a.baseData(r)
		data.Flash = err.Error()
		data.FlashKind = "err"
		data.Term = st.Term
		data.Redirect = st.Redirect
		data.GitName = st.GitName
		data.GitEmail = st.GitEmail
		data.SSHKeys = st.SSHKeys
		a.renderPage(w, "settings", data)
		return
	}
	http.Redirect(w, r, "/settings?ok=1", http.StatusSeeOther)
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
	for _, u := range pw.List() {
		data.Users = append(data.Users, UserRow{Name: u.Name, UID: u.UID, Home: u.Home})
	}
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
	wantAdmin := r.Form.Get("admin") == "1"
	createHome := r.Form.Get("create_home") != "0"

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
	if wantAdmin {
		if err := a.users.AddUserToGroup(username, "sudo"); err != nil {
			_ = a.users.AddUserToGroup(username, "wheel")
		}
	}
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
	http.Redirect(w, r, "/admin/users?ok=1", http.StatusSeeOther)
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
	return data
}

func (a *App) renderPage(w http.ResponseWriter, page string, data *ViewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t := a.pages[page]
	if t == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	_ = t.ExecuteTemplate(w, "layout", data)
}
