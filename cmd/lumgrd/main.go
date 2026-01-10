package main

import (
	"log"
	"os"

	"github.com/hnrobert/lumgr/internal/server"
)

func main() {
	addr := os.Getenv("LUMGR_LISTEN")
	if addr == "" {
		addr = ":14392"
	}

	srv := server.New(server.Config{
		ListenAddr: addr,
		HostRoot:   getenvDefault("LUMGR_HOST_ROOT", "/host"),
	})

	log.Printf("lumgr listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func getenvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}
