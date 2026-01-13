package auth

// Package auth will provide host-backed authentication.
//
// Design goal:
// - Login uses host user database (e.g. /etc/passwd, /etc/shadow).
// - Authorization binds to host privileges (sudo-capable users can modify users/groups).
//
// TODO: Implement parsing and verification using the mounted host files.
