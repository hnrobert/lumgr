package usermgr

// Package usermgr implements user/group management by operating on mounted host files.
//
// Files are expected to be bind-mounted directly under /:
//   /etc/passwd
//   /etc/shadow
//   /etc/group
//   /home/...
//
// This package focuses on safe parsing and safe, atomic updates.
