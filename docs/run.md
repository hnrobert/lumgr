# Running lumgr

## Docker Compose

This only makes sense on a **Linux host**.

On macOS/Windows with Docker Desktop, the container sees the Linux VM filesystem, not your macOS/Windows host user database.

```bash
docker compose up --build
```

Default URL:

- [http://localhost:14392/](http://localhost:14392/)

## Security prerequisites

- Reading/writing `/etc/shadow` typically requires **root**.
- This tool modifies the host account system directly; test on a VM/staging machine first.
