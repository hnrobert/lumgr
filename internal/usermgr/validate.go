package usermgr

import "regexp"

var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validUsername(u string) bool {
	return usernameRe.MatchString(u)
}
