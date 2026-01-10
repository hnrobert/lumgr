package usermgr

// Package usermgr will implement user/group management by operating on host files.
//
// Target operations (planned):
// - list/create/delete users
// - list/create/delete groups
// - set default login directory (home)
// - manage sudo capability by editing host sudoers fragments (optional)
//
// Security model (planned):
// - Only allow mutations if authenticated host user has required privilege.
// - Never elevate beyond what host permits.
