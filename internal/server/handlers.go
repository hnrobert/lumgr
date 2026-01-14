package server

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
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
	var groups []string

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

	for _, g := range groups {
		if g != "" {
			_ = a.users.AddUserToGroup(username, g)
		}
	}

	if mode == config.RegistrationInvite {
		_, _ = a.invites.Consume(code, username, remoteIP(r))
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
		data.Invites = append(data.Invites, InviteRow{ID: inv.ID, UsedCount: inv.UsedCount, MaxUses: inv.MaxUses, ExpiresAt: inv.ExpiresAt, CreateHome: inv.CreateHome, Groups: inv.Groups})
	}

	cfg, _ := a.cfg.Get()
	data.DefaultGroups = cfg.DefaultGroups
	data.AllGroups, _ = a.users.ListGroups()
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
	if _, err := a.invites.Create(usernameFrom(r), maxUses, expiresAt, createHome, groups); err != nil {
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

	data.AllGroups, _ = a.users.ListGroups()
	sort.Strings(data.AllGroups)

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
	for _, g := range groups {
		if g != "" {
			_ = a.users.AddUserToGroup(username, g)
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

	data.EditUser = UserRow{Name: u.Name, UID: u.UID, Home: u.Home, Groups: groups}

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

	a.renderPage(w, "admin_user_edit", data)
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

	setgid := r.Form.Get("setgid") == "1"

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

	if err := a.users.RecursiveChmodHome(username, m, setgid); err != nil {
		logger.Error("RecursiveChmodHome failed for %s: %v", username, err)
		msg := url.QueryEscape(err.Error())
		http.Redirect(w, r, "/admin/users/edit?user="+username+"&flash="+msg, http.StatusSeeOther)
		return
	}
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

	var rows []GroupRow
	list := gp.List()
	// Sort by GID? User didn't specify, but alphabetical usually better or ID. Let's do GID.
	// usermgr.List() sorts by GID.

	for _, g := range list {
		m := strings.Join(g.Members, ", ")
		rows = append(rows, GroupRow{Name: g.Name, GID: g.GID, Members: m})
	}
	data.Groups = rows

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
	http.Redirect(w, r, "/admin/groups?ok=1", http.StatusSeeOther)
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
