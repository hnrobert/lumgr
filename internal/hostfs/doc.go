package hostfs

// Package hostfs provides safe access helpers for files mounted from the host.
//
// Fixed contract:
//   HostRoot = /
//
// Expected mounts (examples):
//   /etc/passwd  -> /etc/passwd
//   /etc/shadow  -> /etc/shadow
//   /etc/group   -> /etc/group
//   /home        -> /home
