package server

import (
	"net/http"
	"time"
)

type Config struct {
	ListenAddr string
}

type Server struct {
	cfg Config
	h   http.Handler
}

func New(cfg Config) *Server {
	mux := http.NewServeMux()

	// Web UI (placeholder)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("lumgr: web ui skeleton (TODO)\n"))
	})

	// API routes (placeholders)
	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"ok\":true}\n"))
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte("{\"error\":\"TODO: host-backed auth\"}\n"))
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte("{\"error\":\"TODO: host user management\"}\n"))
	})

	return &Server{cfg: cfg, h: mux}
}

func (s *Server) ListenAndServe() error {
	httpSrv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
}
