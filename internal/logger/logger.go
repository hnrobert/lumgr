package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

var (
	out     io.Writer = os.Stdout
	logFile *os.File
)

func Init(logDir string) error {
	if logDir == "" {
		return nil
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(logDir, "lumgr.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	out = io.MultiWriter(os.Stdout, f)
	logFile = f
	return nil
}

func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

func Info(format string, args ...interface{}) {
	log(LevelInfo, format, args...)
}

func Warn(format string, args ...interface{}) {
	log(LevelWarn, format, args...)
}

func Error(format string, args ...interface{}) {
	log(LevelError, format, args...)
}

func log(lvl Level, format string, args ...interface{}) {
	now := time.Now().Format("2006/01/02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	var label, colorStart, colorEnd string
	switch lvl {
	case LevelInfo:
		colorStart = "\033[32m" // Green
		label = "[INFO] "
	case LevelWarn:
		colorStart = "\033[33m" // Yellow
		label = "[WARN] "
	case LevelError:
		colorStart = "\033[31m" // Red
		label = "[EROR] "       // 4 chars align
		colorEnd = "\033[0m"
	}
	// File output (no color)
	if logFile != nil {
		line := fmt.Sprintf("%s %s%s\n", now, label, msg)
		logFile.WriteString(line)
	}
	// Stdout (color)
	fmt.Fprintf(os.Stdout, "%s %s%s%s%s\n", now, colorStart, label, colorEnd, msg)
	// 1. Write to Stdout with color
	// Override 'out' usage for separate handling:
	// So we should write separately if we want different formats.
	// Actually MultiWriter writes same bytes to both.
	// but since we want color ONLY on stdout and plain on file, we separate writers.
	// Build string manually to avoid double writing if out is MultiWriter,
}
