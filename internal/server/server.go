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
	app, err := newApp()
	if err != nil {
		// Defer error to ListenAndServe for a single error return path.
		return &Server{cfg: cfg, h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		})}
	}
	return &Server{cfg: cfg, h: app.routes()}
}

func (s *Server) ListenAndServe() error {
	httpSrv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
}
