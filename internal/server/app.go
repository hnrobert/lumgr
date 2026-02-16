package server

import (
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hnrobert/lumgr/internal/auth"
	"github.com/hnrobert/lumgr/internal/config"
	"github.com/hnrobert/lumgr/internal/invite"
	"github.com/hnrobert/lumgr/internal/resmon"
	"github.com/hnrobert/lumgr/internal/usercmd"
)

//go:embed templates/*.html templates/components/*.html
var templatesFS embed.FS

type App struct {
	secret     []byte
	cookieName string
	pages      map[string]*template.Template
	users      *usercmd.Runner
	invites    *invite.Store
	cfg        *config.Store
	resmon     *resmon.Store
	collector  *resmon.Collector

	realtimeMu      sync.RWMutex
	realtimeSamples []resmon.Sample
}

type ViewData struct {
	Authed      bool
	Username    string
	Admin       bool
	HideNav     bool
	RegMode     string
	Flash       string
	FlashKind   string // ok|err|""
	CurrentPage string // template sets the logical current page for nav highlighting

	// show/hide helpers
	ShowSaveAll bool // true when page should display a global "Save all" action

	// settings
	Term            string
	Redirect        string
	Shell           string
	GitName         string
	GitEmail        string
	GitSigningKey   string
	GitSigningPub   string
	SSHPrivateKeys  []string
	SSHKeys         string
	AvailableShells []string
	Umask           string

	// permission helpers (used by perms subtemplate)
	PermFormAction            string
	PermIncludeSpecial        bool
	PermSpecialSetUIDEditable bool
	PermSpecialSetGIDEditable bool
	PermSpecialStickyEditable bool
	PermUmaskFormAction       string
	PermUmaskValue            string
	PermSubmitLabel           string

	// admin
	Users       []UserRow
	SystemUsers []UserRow
	Invites     []InviteRow
	EditUser    UserRow

	// lumgr settings (markdown)
	LumgrWhatEdits     string
	LumgrWhatEditsHTML template.HTML

	// dashboard stats
	TotalUsers   int
	AdminUsers   int
	HomeSize     string
	OSName       string
	OSVersion    string
	OSPrettyName string
	Hostname     string
	Groups       []GroupRow
	SystemGroups []GroupRow
	AllGroups    []string

	// user edit
	FeaturedGroups []string
	OtherGroups    []string
	HomePerms      HomePerms

	// register
	InviteCode string

	// registration settings
	DefaultGroups       []string
	UbuntuDesktopGroups []string

	// resource monitor
	CurrentMetrics     *resmon.Metrics
	ResmonHistory      []resmon.Sample
	ResmonConfig       resmon.Config
	ResmonUsers        []string
	ResmonSelectedUser string
	ResmonLatestUsers  []resmon.UserResource
}

type GroupRow struct {
	Name    string
	GID     int
	Members string
}

type UserRow struct {
	Name   string
	UID    int
	Home   string
	Groups []string
	Umask  string
}

type HomePerms struct {
	UserR, UserW, UserX    bool
	GroupR, GroupW, GroupX bool
	OtherR, OtherW, OtherX bool
	SetUID                 bool
	SetGID                 bool
	Sticky                 bool
	Octal                  string // e.g., "0755" or "2775"
}

type InviteRow struct {
	ID         string
	UsedCount  int
	MaxUses    int
	ExpiresAt  time.Time
	CreateHome bool
	Groups     []string
	Umask      string
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
		// eq/startWith now trim inputs to tolerate accidental whitespace introduced by formatters
		"eq": func(a, b string) bool {
			a = strings.TrimSpace(a)
			b = strings.TrimSpace(b)
			return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
		},
		"contains": func(list []string, s string) bool {
			for _, v := range list {
				if v == s {
					return true
				}
			}
			return false
		},
		"startsWith": func(s, p string) bool { return strings.HasPrefix(strings.TrimSpace(s), strings.TrimSpace(p)) },
		"trim":       func(s string) string { return strings.TrimSpace(s) },
		"base":       func(p string) string { return filepath.Base(strings.TrimSpace(p)) },
		"RenderHTML": func(s string) template.HTML { return RenderMarkdown(s) },
		"toJSON": func(v any) template.JS {
			b, err := json.Marshal(v)
			if err != nil {
				return template.JS("null")
			}
			return template.JS(b)
		},
		"bytes": func(v uint64) string {
			const unit = 1024
			if v < unit {
				return fmt.Sprintf("%d B", v)
			}
			div, exp := uint64(unit), 0
			for n := v / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %ciB", float64(v)/float64(div), "KMGTPE"[exp])
		},
	})

	pages := map[string]*template.Template{}
	for _, page := range []string{
		"login",
		"register",
		"dashboard",
		"settings_shell",
		"settings_ssh",
		"settings_git",
		"settings_filesystem",
		"settings_security",
		"admin_users",
		"admin_groups",
		"admin_invites",
		"admin_user_edit",
		"admin_lumgr_settings",
		"admin_resources",
	} {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		// Each page file defines the same block names (title/content).
		// Parse layout, perms subtemplate, then page to override blocks.
		if _, err := t.ParseFS(templatesFS, "templates/layout.html", "templates/components/perms_table.html", "templates/"+page+".html"); err != nil {
			return nil, err
		}
		pages[page] = t
	}

	invStore := invite.NewStore(invite.DefaultPath())
	_ = invStore.Ensure()

	cfgStore := config.NewStore(config.DefaultPath())
	_ = cfgStore.Ensure()

	rmStore := resmon.NewStore(resmon.DefaultPath())
	_ = rmStore.Ensure()
	_ = rmStore.Load()
	procRoot := "/proc"
	if st, err := os.Stat("/host/proc"); err == nil && st.IsDir() {
		procRoot = "/host/proc"
	}
	rmCollector := resmon.NewCollector(procRoot)

	app := &App{
		secret:     secretRaw,
		cookieName: auth.DefaultCookieName,
		pages:      pages,
		users:      usercmd.New(),
		invites:    invStore,
		cfg:        cfgStore,
		resmon:     rmStore,
		collector:  rmCollector,
	}
	app.startResmonLoop()
	return app, nil
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/logout", a.requireAuth(a.handleLogout))
	mux.HandleFunc("/register", a.handleRegister)
	mux.HandleFunc("/register/complete", a.handleRegisterComplete)

	mux.HandleFunc("/", a.requireAuth(a.handleDashboard))
	mux.HandleFunc("/settings", a.requireAuth(a.handleSettings))
	mux.HandleFunc("/settings/shell", a.requireAuth(a.handleSettingsShell))
	mux.HandleFunc("/settings/ssh", a.requireAuth(a.handleSettingsSSH))
	mux.HandleFunc("/settings/ssh/keygen", a.requireAuth(a.handleSettingsSSHKeygen))
	mux.HandleFunc("/settings/ssh/key/delete", a.requireAuth(a.handleSettingsSSHKeyDelete))
	mux.HandleFunc("/settings/ssh/key/passphrase", a.requireAuth(a.handleSettingsSSHKeyPassphrase))
	mux.HandleFunc("/settings/ssh/key/export", a.requireAuth(a.handleSettingsSSHKeyExport))
	mux.HandleFunc("/settings/git", a.requireAuth(a.handleSettingsGit))
	mux.HandleFunc("/settings/filesystem", a.requireAuth(a.handleSettingsFilesystem))
	mux.HandleFunc("/settings/security", a.requireAuth(a.handleSettingsSecurity))
	mux.HandleFunc("/settings/password", a.requireAuth(a.handleSettingsPassword))
	mux.HandleFunc("/settings/umask", a.requireAuth(a.handleSettingsUmask))
	mux.HandleFunc("/settings/chmod", a.requireAuth(a.handleSettingsChmod))

	mux.HandleFunc("/admin/users", a.requireAdmin(a.handleAdminUsers))
	mux.HandleFunc("/admin/users/create", a.requireAdmin(a.handleAdminUsersCreate))
	mux.HandleFunc("/admin/users/delete", a.requireAdmin(a.handleAdminUsersDelete))
	mux.HandleFunc("/admin/users/edit", a.requireAdmin(a.handleAdminUserEdit))
	mux.HandleFunc("/admin/users/update_groups", a.requireAdmin(a.handleAdminUserUpdateGroups))
	mux.HandleFunc("/admin/users/chmod", a.requireAdmin(a.handleAdminUserChmod))
	mux.HandleFunc("/admin/users/umask", a.requireAdmin(a.handleAdminUserUmask))

	mux.HandleFunc("/admin/groups", a.requireAdmin(a.handleAdminGroups))
	mux.HandleFunc("/admin/groups/create", a.requireAdmin(a.handleAdminGroupsCreate))
	mux.HandleFunc("/admin/groups/delete", a.requireAdmin(a.handleAdminGroupsDelete))

	mux.HandleFunc("/admin/invites", a.requireAdmin(a.handleAdminInvites))
	mux.HandleFunc("/admin/invites/create", a.requireAdmin(a.handleAdminInvitesCreate))
	mux.HandleFunc("/admin/invites/delete", a.requireAdmin(a.handleAdminInvitesDelete))
	mux.HandleFunc("/admin/settings/registration", a.requireAdmin(a.handleAdminRegistrationMode))
	mux.HandleFunc("/admin/lumgr_settings", a.requireAdmin(a.handleAdminLumgrSettings))
	mux.HandleFunc("/admin/resources", a.requireAdmin(a.handleAdminResources))
	mux.HandleFunc("/admin/resources/config", a.requireAdmin(a.handleAdminResourcesConfig))

	// Static assets
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("/usr/local/share/lumgrd/assets/"))))

	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"ok\":true}\n"))
	})
	mux.HandleFunc("/api/resmon/current", a.requireAdmin(a.handleAPIResmonCurrent))

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

func (a *App) startResmonLoop() {
	if a == nil || a.collector == nil || a.resmon == nil || a.cfg == nil {
		return
	}
	go func() {
		lastPersistAt := time.Time{}
		for {
			cfg, err := a.cfg.Get()
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			rc := cfg.ResmonConfig.WithDefaults()
			persistInterval := time.Duration(rc.IntervalSeconds) * time.Second
			if persistInterval < 1*time.Second {
				persistInterval = 1 * time.Second
			}
			if rc.Enabled {
				m, us, err := a.collector.Collect(rc)
				if err == nil {
					now := time.Now().UTC()
					sm := resmon.Sample{Timestamp: now, Metrics: m, UserStats: us}
					a.appendRealtimeSample(sm)
					if lastPersistAt.IsZero() || now.Sub(lastPersistAt) >= persistInterval {
						agg := aggregateResmonWindow(a.getRealtimeSamples())
						_ = a.resmon.Append(agg, rc.RetentionDays)
						lastPersistAt = now
					}
				}
				_ = a.resmon.Prune(rc.RetentionDays)
			} else {
				a.clearRealtimeSamples()
			}
			time.Sleep(1 * time.Second)
		}
	}()
}

func (a *App) appendRealtimeSample(sm resmon.Sample) {
	a.realtimeMu.Lock()
	defer a.realtimeMu.Unlock()
	a.realtimeSamples = append(a.realtimeSamples, sm)
	if len(a.realtimeSamples) > 30 {
		a.realtimeSamples = a.realtimeSamples[len(a.realtimeSamples)-30:]
	}
}

func (a *App) clearRealtimeSamples() {
	a.realtimeMu.Lock()
	defer a.realtimeMu.Unlock()
	a.realtimeSamples = nil
}

func (a *App) getRealtimeSamples() []resmon.Sample {
	a.realtimeMu.RLock()
	defer a.realtimeMu.RUnlock()
	if len(a.realtimeSamples) == 0 {
		return nil
	}
	out := make([]resmon.Sample, len(a.realtimeSamples))
	copy(out, a.realtimeSamples)
	return out
}

func aggregateResmonWindow(samples []resmon.Sample) resmon.Sample {
	if len(samples) == 0 {
		now := time.Now().UTC()
		return resmon.Sample{Timestamp: now, Metrics: resmon.Metrics{Timestamp: now}}
	}
	var cpuUser, cpuSystem, cpuIdle, cpuUsage float64
	var memTotalSum, memUsedSum, memAvailSum uint64
	var diskReadSum, diskWriteSum, netRxSum, netTxSum uint64
	latest := samples[len(samples)-1]

	type userAgg struct {
		count  int
		cpuSum float64
		memSum uint64
	}
	userMap := map[string]*userAgg{}

	for _, sm := range samples {
		m := sm.Metrics
		cpuUser += m.CPUUser
		cpuSystem += m.CPUSystem
		cpuIdle += m.CPUIdle
		cpuUsage += m.CPUUsage
		memTotalSum += m.MemTotal
		memUsedSum += m.MemUsed
		memAvailSum += m.MemAvailable
		diskReadSum += m.DiskReadBytes
		diskWriteSum += m.DiskWriteBytes
		netRxSum += m.NetworkRxBytes
		netTxSum += m.NetworkTxBytes

		for _, u := range sm.UserStats {
			ua := userMap[u.Username]
			if ua == nil {
				ua = &userAgg{}
				userMap[u.Username] = ua
			}
			ua.count++
			ua.cpuSum += u.CPU
			ua.memSum += u.MemoryBytes
		}
	}

	n := float64(len(samples))
	ts := latest.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	out := resmon.Sample{
		Timestamp: ts,
		Metrics: resmon.Metrics{
			Timestamp:      ts,
			CPUUser:        cpuUser / n,
			CPUSystem:      cpuSystem / n,
			CPUIdle:        cpuIdle / n,
			CPUUsage:       cpuUsage / n,
			MemTotal:       uint64(float64(memTotalSum) / n),
			MemUsed:        uint64(float64(memUsedSum) / n),
			MemAvailable:   uint64(float64(memAvailSum) / n),
			DiskReadBytes:  diskReadSum,
			DiskWriteBytes: diskWriteSum,
			NetworkRxBytes: netRxSum,
			NetworkTxBytes: netTxSum,
		},
	}

	users := make([]resmon.UserResource, 0, len(userMap))
	for name, ua := range userMap {
		if ua.count <= 0 {
			continue
		}
		users = append(users, resmon.UserResource{
			Username:    name,
			CPU:         ua.cpuSum / float64(ua.count),
			MemoryBytes: uint64(float64(ua.memSum) / float64(ua.count)),
		})
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].CPU == users[j].CPU {
			return users[i].MemoryBytes > users[j].MemoryBytes
		}
		return users[i].CPU > users[j].CPU
	})
	if len(users) > 20 {
		users = users[:20]
	}
	out.UserStats = users
	return out
}
