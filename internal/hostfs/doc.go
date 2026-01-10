package hostfs

// Package hostfs provides access helpers for files mounted from the host.
//
// Expected mounts (examples):
//   /etc/passwd  -> /host/etc/passwd
//   /etc/shadow  -> /host/etc/shadow
//   /etc/group   -> /host/etc/group
//   /home        -> /host/home
//
// TODO: Add safe open/write helpers, atomic writes, backup, and validation.
