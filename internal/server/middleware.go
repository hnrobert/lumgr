package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/hnrobert/lumgr/internal/auth"
)

type ctxKey string

const (
	ctxUsername ctxKey = "username"
	ctxAdmin    ctxKey = "admin"
)

func (a *App) withAuthContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, admin := a.readAuth(r)
		ctx := r.Context()
		if username != "" {
			ctx = context.WithValue(ctx, ctxUsername, username)
			ctx = context.WithValue(ctx, ctxAdmin, admin)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) readAuth(r *http.Request) (string, bool) {
	// Prefer cookie.
	if c, err := r.Cookie(a.cookieName); err == nil && c.Value != "" {
		if cl, err := auth.ParseHS256(a.secret, c.Value); err == nil {
			return cl.Username, cl.Admin
		}
	}
	// Fallback: Authorization: Bearer <token>
	authz := r.Header.Get("Authorization")
	if authz != "" {
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			if cl, err := auth.ParseHS256(a.secret, strings.TrimSpace(parts[1])); err == nil {
				return cl.Username, cl.Admin
			}
		}
	}
	return "", false
}

func usernameFrom(r *http.Request) string {
	if v := r.Context().Value(ctxUsername); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func isAdminFrom(r *http.Request) bool {
	if v := r.Context().Value(ctxAdmin); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func (a *App) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if usernameFrom(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

func (a *App) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !isAdminFrom(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}
