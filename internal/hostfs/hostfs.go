package hostfs

import (
	"errors"
	"path/filepath"
	"strings"
)

// HostRoot is the fixed mount point for the Linux host filesystem inside the container.
const HostRoot = "/host"

var ErrInvalidPath = errors.New("invalid host path")

// Path joins HostRoot with a relative path (no leading slash).
// Example: Path("etc/passwd") -> /host/etc/passwd
func Path(rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "/")
	clean := filepath.Clean(rel)
	if clean == "." || clean == "" {
		return "", ErrInvalidPath
	}
	if strings.HasPrefix(clean, "..") {
		return "", ErrInvalidPath
	}
	return filepath.Join(HostRoot, clean), nil
}

// Abs maps an absolute host path (e.g. /home/alice/.ssh/authorized_keys)
// into the container path (e.g. /host/home/alice/.ssh/authorized_keys).
func Abs(abs string) (string, error) {
	if abs == "" || !strings.HasPrefix(abs, "/") {
		return "", ErrInvalidPath
	}
	clean := filepath.Clean(abs)
	if !strings.HasPrefix(clean, "/") {
		return "", ErrInvalidPath
	}
	return filepath.Join(HostRoot, strings.TrimPrefix(clean, "/")), nil
}
