# Authentication & authorization (planned)

This repository currently provides only a scaffold. The authentication and authorization model below is the intended design and will be implemented incrementally.

## Login

- Users authenticate with **username + password**.
- The password is verified against the host account database mounted into the container (e.g. `/host/etc/shadow`).

## Session / API authentication

- After a successful login, the server issues a **JWT access token**.
- The Web UI and API calls authenticate using `Authorization: Bearer <token>`.

## Authorization model

- Authorization is bound to the authenticated host user’s *real* privilege.
- Mutating operations (creating users, modifying groups, adjusting sudo-related permissions, etc.) will only be allowed when the authenticated host user is permitted to perform them.

## Notes

- Reading `/etc/shadow` and performing many account-management operations generally require **root**.
- This tool directly edits the host account system; improper edits can lock you out of the host.
