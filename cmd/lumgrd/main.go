package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/hnrobert/lumgr/internal/logger"
	"github.com/hnrobert/lumgr/internal/server"
)

func main() {
	dataDir := "lumgr_data"
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 2776); err != nil {
		log.Printf("Failed to create data dir: %v", err)
	}

	// 2. Initialize Logger
	if err := logger.Init(dataDir); err != nil {
		log.Fatalf("Failed to init logger: %v", err)
	}
	defer logger.Close()

	// 3. Permission Fix (World Writable)
	// Make dataDir and all contents writable by all users so host user can access/edit.
	if err := os.Chmod(dataDir, 2776); err != nil {
		logger.Error("Failed to chmod data dir: %v", err)
	}

	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// If we create new files, they might have restrictive umask.
		// Force 2777 or 2666.
		m := os.FileMode(2666)
		if info.IsDir() {
			m = 2777
		}
		return os.Chmod(path, m)
	})
	if err != nil {
		logger.Error("Failed to recursive chmod data dir: %v", err)
	}

	addr := os.Getenv("LUMGR_LISTEN")
	if addr == "" {
		addr = ":14392"
	}

	srv := server.New(server.Config{
		ListenAddr: addr,
	})

	logger.Info("lumgr listening on %s", addr)

	if err := srv.ListenAndServe(); err != nil {
		logger.Error("Server shutdown: %v", err)
		os.Exit(1)
	}
}
