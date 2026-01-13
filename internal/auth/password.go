package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/hnrobert/lumgr/internal/hostfs"
	"github.com/hnrobert/lumgr/internal/usermgr"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserLocked         = errors.New("user is locked")
	ErrUnsupportedHash    = errors.New("unsupported password hash")
)

func shadowPath() (string, error) {
	return hostfs.Path(hostfs.EtcShadowRel)
}

func VerifyPassword(username, password string) error {
	path, err := shadowPath()
	if err != nil {
		return err
	}
	sh, err := usermgr.LoadShadow(path)
	if err != nil {
		return err
	}
	se := sh.Find(username)
	if se == nil {
		return ErrInvalidCredentials
	}
	if se.Hash == "" || se.Hash == "!" || se.Hash == "*" || strings.HasPrefix(se.Hash, "!") || strings.HasPrefix(se.Hash, "*") {
		return ErrUserLocked
	}
	if ok, err := verifyCrypt(se.Hash, password); err != nil {
		if errors.Is(err, ErrUnsupportedHash) {
			ok2, err2 := verifyWithSu(username, password)
			if err2 != nil {
				return err2
			}
			if !ok2 {
				return ErrInvalidCredentials
			}
			return nil
		}
		return err
	} else if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

func verifyCrypt(hash, password string) (bool, error) {
	// Support common crypt formats:
	// $1$ (md5-crypt), $5$ (sha256-crypt), $6$ (sha512-crypt), $2a/$2y (bcrypt).
	// Note: this does NOT support newer formats like yescrypt.
	var crypters []crypt.Crypter
	crypters = append(crypters, sha512_crypt.New())
	crypters = append(crypters, sha256_crypt.New())
	crypters = append(crypters, md5_crypt.New())

	// Try known crypters. Verify returns nil on success.
	for _, c := range crypters {
		if err := c.Verify(hash, []byte(password)); err == nil {
			return true, nil
		}
	}

	// Detect an obviously unsupported hash prefix.
	// Ubuntu commonly uses yescrypt ($y$).
	if strings.HasPrefix(hash, "$y$") || strings.HasPrefix(hash, "$7$") || strings.HasPrefix(hash, "$2") {
		return false, ErrUnsupportedHash
	}
	return false, nil
}

func IsAdmin(username string) (bool, error) {
	// Derive admin from sudo-capable group membership.
	// Uses /etc/group parsing (mounted from host).
	groupPath, err := hostfs.Path(hostfs.EtcGroupRel)
	if err != nil {
		return false, err
	}
	gr, err := usermgr.LoadGroup(groupPath)
	if err != nil {
		return false, err
	}
	for _, gname := range []string{"sudo", "wheel"} {
		g := gr.Find(gname)
		if g == nil {
			continue
		}
		for _, m := range g.Members {
			if m == username {
				return true, nil
			}
		}
	}
	return false, nil
}

func HumanAuthError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidCredentials):
		return "Invalid username or password."
	case errors.Is(err, ErrUserLocked):
		return "This account is locked."
	case errors.Is(err, ErrUnsupportedHash):
		return "This host uses an uncommon password hash format; trying system authentication."
	default:
		return fmt.Sprintf("Authentication failed: %v", err)
	}
}
