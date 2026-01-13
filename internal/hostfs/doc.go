package hostfs

// Package hostfs provides safe access helpers for files mounted from the host.
//
// Fixed contract:
//   HostRoot = /host
//
// Expected mounts (examples):
//   /etc/passwd  -> /host/etc/passwd
//   /etc/shadow  -> /host/etc/shadow
//   /etc/group   -> /host/etc/group
//   /home        -> /host/home
