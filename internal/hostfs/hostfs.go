package hostfs

import (
	"errors"
	"path/filepath"
	"strings"
)

// HostRoot is the fixed root for host file access inside the container.
//
// In the current container contract, host account files are bind-mounted directly
// to their standard locations (e.g. /etc/passwd, /etc/shadow, /etc/group, /home).
const HostRoot = "/"

var ErrInvalidPath = errors.New("invalid host path")

// Path joins HostRoot with a relative path (no leading slash).
// Example: Path("etc/passwd") -> /etc/passwd
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
// into the container path (e.g. /home/alice/.ssh/authorized_keys).
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
