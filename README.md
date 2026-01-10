# lumgr

Linux User Manager — a simple web panel to manage Linux host users.

Goal: run a Web UI (HTTP port `14392`) in a container, and manage the Linux host’s users/groups/default home directory (and optionally sudo-related privileges) by bind-mounting the host account database files into the container.

> Status: scaffold/framework only. API routes and host-backed authentication/authorization are placeholders (`TODO`).

## Architecture

```text
Alpine lumgr

  |
  |  open(), write()
  v
Host kernel

  |
  v
Host /etc/passwd, /etc/shadow, /etc/group, /home

  |
  v
sshd / sudo / login
```

## Run (Docker Compose)

This only makes sense on a **Linux host**.

On macOS/Windows with Docker Desktop, the container sees the Linux VM filesystem, not your macOS/Windows host user database.

```bash
docker compose up --build
```

Default URL: `http://localhost:14392/`

## Host mounts

The container expects the host root to be mounted at `/host`, with these bind mounts:

```text
- /etc/passwd:/host/etc/passwd
- /etc/shadow:/host/etc/shadow
- /etc/group:/host/etc/group
- /home:/host/home
```

If/when sudo management is implemented, it will typically also require mounting `/etc/sudoers` and/or `/etc/sudoers.d`.

## Security & prerequisites

- Reading/writing `/etc/shadow` typically requires **root**; `docker-compose.yml` runs the container as `user: "0:0"`.
- This tool modifies the host account system directly. A mistake can lock you out of the host. Test on a VM/staging machine first.
- Planned model: Web UI login is fully backed by host user information, and authorization is bound to the authenticated host user’s actual privilege (e.g. sudo-capable users can perform higher-risk actions).

## Development

Run the placeholder server locally (currently only skeleton routes like `/` and `/api/healthz`):

```bash
make run
```

## Environment variables

- `LUMGR_LISTEN`: listen address (default `:14392`)
- `LUMGR_HOST_ROOT`: host mount root (default `/host`)
