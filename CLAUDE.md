# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`lumgr` is a containerized Linux User Manager - a web-based interface for managing users, groups, permissions, and SSH keys on Linux systems. It runs as a Docker container with direct access to host system files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/home`).

- **Language**: Go 1.22+ (go.mod specifies 1.22)
- **Framework**: Standard library `net/http` (no external web framework)
- **Default Port**: 14392
- **Key Dependencies**: `github.com/golang-jwt/jwt/v5`, `github.com/GehirnInc/crypt` (SHA-512 passwords), `github.com/creack/pty` (terminal handling)

## Build and Run Commands

```bash
# Build the binary
make build

# Run locally (development)
make run
# Server runs on :14392 by default

# Run tests (currently none exist)
make test

# Docker operations
make build-docker     # Build Docker image
make run-docker       # Start with Docker Compose
make stop-docker      # Stop Docker Compose
make restart-docker   # Rebuild and restart
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LUMGR_LISTEN` | `:14392` | HTTP listen address |
| `LUMGR_JWT_SECRET` | (ephemeral) | JWT signing secret - set for persistent sessions |

## Architecture Overview

The codebase follows a clean layered architecture:

```text
cmd/lumgrd/main.go          # Entry point
internal/
  ├── auth/                 # JWT tokens, password hashing, sudo verification
  ├── config/               # JSON config persistence (registration mode, default groups)
  ├── invite/               # Invitation system with expiration and usage limits
  ├── logger/               # Structured logging
  ├── server/               # HTTP layer: handlers, middleware, templates
   ├── resmon/               # System resource collector + history store (prefers /host/proc, falls back to /proc)
  ├── usercmd/              # Wrapper for shell commands (useradd, usermod, etc.)
  ├── usermgr/              # Core business logic: passwd/shadow/group parsers
  └── hostfs/               # Host filesystem access abstraction
```

### Key Architectural Patterns

1. **Host Filesystem Access via `internal/hostfs/`**
   - All host file access goes through `hostfs.Path()` and `hostfs.Abs()`
   - `HostRoot = "/"` - host files are bind-mounted to standard paths in container
   - Atomic writes via `hostfs.WriteFileAtomic()` - uses temp file + rename, with fallback to in-place rewrite for bind-mounted files (handles EBUSY/EXDEV/EPERM errors)

2. **User Management via `internal/usermgr/`**
   - `Manager` struct handles user/group CRUD operations
   - Parses/writes `/etc/passwd`, `/etc/shadow`, `/etc/group` directly
   - Admin determination: membership in `sudo` or `wheel` group
   - Note: `internal/usercmd/` is a separate package that also handles user operations with its own `Runner` struct; both are used by the server layer for different purposes

3. **Server Layer in `internal/server/`**
   - `App` struct in `app.go` holds application state (templates, stores, JWT secret)
   - Middleware in `middleware.go`: `requireAuth`, `requireAdmin`
   - Context keys: `ctxUsername`, `ctxAdmin` for request-scoped auth data
   - Embedded templates in `templates/` directory

4. **Authentication**
   - JWT tokens with HS256, stored in HTTP-only cookies
   - Cookie auth or `Authorization: Bearer <token>` header
   - Admin status determined by `usermgr.IsAdmin()` (sudo/wheel group membership)

5. **Data Persistence**
   - `lumgr_data/config.json` - Registration mode and default groups
   - `lumgr_data/invites.json` - Invitation codes
   - `lumgr_data/resmon_history/` - Persisted resmon history directory with daily files (`YYYY-MM-DD.json`) when resource monitoring is enabled
   - Settings per user in `lumgr_data/settings/<username>.json`

## Important Constants and Thresholds

- **System users**: UID < 1000 are hidden/collapsed in UI
- **System groups**: GID < 1000 are hidden/collapsed in UI
- **User ID allocation**: Starts at 1000
- **Group ID allocation**: Starts at 1000
- **Ubuntu desktop groups**: `video`, `audio`, `input`, `plugdev`, `cdrom`, `dialout`, `lpadmin`, `adm`, `netdev`

## Special File Handling

- **`~/.ssh/` directory**: Excluded from recursive chmod operations
- **`.bashrc` / `.zshrc`**: Auto-sourced to load `~/.lumgrc`
- **`.bashrc` templates**: Copied from `assets/.bashrc.*.default` on user creation
- **OS detection**: Reads `/etc/os-release` for Ubuntu-specific handling

## Security Considerations

This tool directly modifies critical system files. Key points:

- All file writes to `/etc/passwd`, `/etc/shadow`, `/etc/group` use atomic writes
- Shadow file permissions: `0600`
- Password hashing uses `github.com/GehirnInc/crypt` (SHA-512)
- JWT secrets: auto-generated with 32-byte minimum; padded if too short
- Admin verification checks real sudo/wheel group membership at login

## Registration Modes

Configured via `internal/config/store.go`:

- **closed** (default): Only admins can create users (referred to as "Admin Only" in UI)
- **open**: Anyone can register; configurable default groups
- **invite**: Registration requires valid invite code with expiration/usage limits

## Template System

- Base template: `templates/layout.html` with block-based inheritance
- Page templates define `title` and `content` blocks
- Template functions: `eq` (constant-time string compare), `contains` (slice membership)
- All pages use the same `ViewData` struct for context
