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

Inside the container, host account files are bind-mounted directly to their
standard locations.

Expected bind mounts:

- `/etc/passwd` -> `/etc/passwd`
- `/etc/shadow` -> `/etc/shadow`
- `/etc/group` -> `/etc/group`
- `/home` -> `/home`

If/when sudo management is implemented, it will typically also require mounting:

- `/etc/sudoers` and/or `/etc/sudoers.d`

## Port

- HTTP: `14392`
