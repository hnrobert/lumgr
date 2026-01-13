package usermgr

import "regexp"

var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validUsername(u string) bool {
	return usernameRe.MatchString(u)
}

// ValidUsername enforces Ubuntu-style username requirements:
// lowercase letters/digits/underscore/dash, starting with a letter or underscore.
func ValidUsername(u string) bool {
	return validUsername(u)
}
