package server

import (
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/hnrobert/lumgr/internal/auth"
	"github.com/hnrobert/lumgr/internal/invite"
	"github.com/hnrobert/lumgr/internal/usercmd"
)

//go:embed templates/*.html
var templatesFS embed.FS

type App struct {
	secret     []byte
	cookieName string
	pages      map[string]*template.Template
	users      *usercmd.Runner
	invites    *invite.Store
}

type ViewData struct {
	Authed    bool
	Username  string
	Admin     bool
	Flash     string
	FlashKind string // ok|err|""

	// settings
	Term     string
	Redirect string
	GitName  string
	GitEmail string
	SSHKeys  string

	// admin
	Users   []UserRow
	Invites []InviteRow

	// register
	InviteCode string
}

type UserRow struct {
	Name string
	UID  int
	Home string
}

type InviteRow struct {
	ID         string
	UsedCount  int
	MaxUses    int
	ExpiresAt  time.Time
	CreateHome bool
}

func newApp() (*App, error) {
	secretText := os.Getenv("LUMGR_JWT_SECRET")
	if secretText == "" {
		// Generate ephemeral secret if not configured.
		s, err := auth.NewRandomSecretB64(32)
		if err != nil {
			return nil, err
		}
		secretText = s
	}
	secretRaw, err := base64.RawURLEncoding.DecodeString(secretText)
	if err != nil {
		// Fallback: accept raw string.
		secretRaw = []byte(secretText)
	}
	if len(secretRaw) < 16 {
		// Avoid trivially weak secrets.
		pad := make([]byte, 16)
		copy(pad, secretRaw)
		secretRaw = pad
	}

	base := template.New("layout.html").Funcs(template.FuncMap{
		"eq": func(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 },
	})

	pages := map[string]*template.Template{}
	for _, page := range []string{"login", "register", "dashboard", "settings", "admin_users", "admin_invites"} {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		// Each page file defines the same block names (title/content).
		// Parse layout first, then page to override blocks.
		if _, err := t.ParseFS(templatesFS, "templates/layout.html", "templates/"+page+".html"); err != nil {
			return nil, err
		}
		pages[page] = t
	}

	invStore := invite.NewStore(invite.DefaultPath())
	_ = invStore.Ensure()

	return &App{
		secret:     secretRaw,
		cookieName: auth.DefaultCookieName,
		pages:      pages,
		users:      usercmd.New(),
		invites:    invStore,
	}, nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("/register", a.handleRegister)
	mux.HandleFunc("/register/complete", a.handleRegisterComplete)

	mux.HandleFunc("/", a.requireAuth(a.handleDashboard))
	mux.HandleFunc("/settings", a.requireAuth(a.handleSettings))

	mux.HandleFunc("/admin/users", a.requireAdmin(a.handleAdminUsers))
	mux.HandleFunc("/admin/users/create", a.requireAdmin(a.handleAdminUsersCreate))
	mux.HandleFunc("/admin/users/delete", a.requireAdmin(a.handleAdminUsersDelete))

	mux.HandleFunc("/admin/invites", a.requireAdmin(a.handleAdminInvites))
	mux.HandleFunc("/admin/invites/create", a.requireAdmin(a.handleAdminInvitesCreate))

	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"ok\":true}\n"))
	})

	return a.withAuthContext(mux)
}

func (a *App) issueCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
}

func (a *App) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   -1,
	})
}
