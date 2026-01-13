package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/hnrobert/lumgr/internal/auth"
	"github.com/hnrobert/lumgr/internal/usermgr"
)

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if usernameFrom(r) != "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		a.renderPage(w, "login", &ViewData{})
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
		a.renderPage(w, "login", &ViewData{Flash: "Username and password are required.", FlashKind: "err"})
		return
	}
	if err := auth.VerifyPassword(username, password); err != nil {
		a.renderPage(w, "login", &ViewData{Flash: auth.HumanAuthError(err), FlashKind: "err"})
		return
	}
	admin, _ := auth.IsAdmin(username)
	tok, err := auth.SignHS256(a.secret, username, admin, 24*time.Hour)
	if err != nil {
		a.renderPage(w, "login", &ViewData{Flash: "Failed to create session.", FlashKind: "err"})
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
	home := strings.TrimSpace(r.Form.Get("home"))
	shell := strings.TrimSpace(r.Form.Get("shell"))
	wantAdmin := r.Form.Get("admin") == "1"

	if username == "" || password == "" {
		http.Redirect(w, r, "/admin/users?err=1", http.StatusSeeOther)
		return
	}
	if home == "" {
		home = "/home/" + username
	}
	if shell == "" {
		shell = "/bin/bash"
	}

	if err := a.users.AddUser(username, home, shell); err != nil {
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
	data := &ViewData{Authed: user != "", Username: user, Admin: admin}
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
