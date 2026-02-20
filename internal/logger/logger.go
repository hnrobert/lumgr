package logger

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"
)

type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

var (
	logFile     *os.File
	logDir      string
	currentDay  string
	logMu       sync.Mutex
	fileLogging bool
)

func Init(logDir string) error {
	if logDir == "" {
		return nil
	}
	// If caller passes /lumgr_data, write logs to /lumgr_data/logs.
	// If caller already passes .../logs, keep it as-is.
	resolved := logDir
	if path.Base(filepath.ToSlash(logDir)) != "logs" {
		resolved = filepath.Join(logDir, "logs")
	}

	if err := os.MkdirAll(resolved, 0777); err != nil {
		return err
	}
	// Enforce world permissions
	_ = os.Chmod(resolved, 0777)

	logMu.Lock()
	defer logMu.Unlock()
	logDir = resolved
	fileLogging = true
	if err := rotateLocked(time.Now()); err != nil {
		fileLogging = false
		return err
	}
	return nil
}

func Close() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
	fileLogging = false
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
	nowTime := time.Now()
	now := nowTime.Format("2006/01/02 15:04:05")
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

	// File output (no color), with daily rollover
	if fileLogging {
		line := fmt.Sprintf("%s %s%s\n", now, label, msg)
		logMu.Lock()
		if err := rotateLocked(nowTime); err == nil && logFile != nil {
			_, _ = logFile.WriteString(line)
		}
		logMu.Unlock()
	}

	// Stdout (color)
	fmt.Fprintf(os.Stdout, "%s %s%s%s%s\n", now, colorStart, label, colorEnd, msg)
}

func rotateLocked(t time.Time) error {
	if logDir == "" {
		return nil
	}
	day := t.Format("2006-01-02")
	if logFile != nil && currentDay == day {
		return nil
	}
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}

	filePath := filepath.Join(logDir, day+".log")
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	_ = os.Chmod(filePath, 0666)
	logFile = f
	currentDay = day
	return nil
}
