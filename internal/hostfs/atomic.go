package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/hnrobert/lumgr/internal/logger"
)

var globalMu sync.Mutex
var fileMu = map[string]*sync.Mutex{}

func muFor(path string) *sync.Mutex {
	globalMu.Lock()
	defer globalMu.Unlock()
	if m := fileMu[path]; m != nil {
		return m
	}
	m := &sync.Mutex{}
	fileMu[path] = m
	return m
}

func ReadFile(path string) ([]byte, error) {
	m := muFor(path)
	m.Lock()
	defer m.Unlock()
	return os.ReadFile(path)
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	m := muFor(path)
	m.Lock()
	defer m.Unlock()

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".lumgr-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		// If the target path is a bind-mounted file, replacing it via rename
		// fails with errors like EBUSY/EXDEV. Fall back to an in-place rewrite.
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EPERM) {
			logger.Warn("WriteFileAtomic rename failed for %s (%v); falling back to in-place rewrite", path, err)
			f, err2 := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, perm)
			if err2 != nil {
				return err
			}
			if _, err2 := f.Write(data); err2 != nil {
				_ = f.Close()
				return err2
			}
			_ = f.Sync()
			if err2 := f.Close(); err2 != nil {
				return err2
			}
			return nil
		}
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func CopyFilePerms(dst, src string) (os.FileMode, error) {
	st, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	return st.Mode().Perm(), nil
}

func EnsureDir(path string, perm os.FileMode) error {
	m := muFor(path)
	m.Lock()
	defer m.Unlock()
	return os.MkdirAll(path, perm)
}

func EnsureFile(path string, perm os.FileMode) error {
	m := muFor(path)
	m.Lock()
	defer m.Unlock()
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	return f.Close()
}

func WriteReaderAtomic(path string, r io.Reader, perm os.FileMode) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, b, perm)
}
