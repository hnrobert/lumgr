package usermgr

// Package usermgr implements user/group management by operating on mounted host files.
//
// Files are expected to be bind-mounted under /host:
//   /host/etc/passwd
//   /host/etc/shadow
//   /host/etc/group
//   /host/home/...
//
// This package focuses on safe parsing and safe, atomic updates.
