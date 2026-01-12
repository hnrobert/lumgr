# Architecture

`lumgr` runs as a containerized HTTP service that operates on the host’s account database files via bind mounts.

```text
lumgr (container)
  |
  |  open(), write()
  v
host kernel
  |
  v
host /etc/passwd, /etc/shadow, /etc/group, /home
  |
  v
sshd / sudo / login
```

## Host filesystem contract

Inside the container, the host filesystem is exposed at a fixed path:

- Host root (fixed): `/host`

Expected bind mounts:

- `/etc/passwd` -> `/host/etc/passwd`
- `/etc/shadow` -> `/host/etc/shadow`
- `/etc/group` -> `/host/etc/group`
- `/home` -> `/host/home`

If/when sudo management is implemented, it will typically also require mounting:

- `/etc/sudoers` and/or `/etc/sudoers.d`

## Port

- HTTP: `14392`
