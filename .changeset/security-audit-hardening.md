---
"@vex-chat/spire": patch
---

Passwords are now hashed with argon2id (via a transparent on-login migration from the previous algorithm). JWT tokens are signed with a dedicated secret instead of reusing the server's persistent key pair, so all existing sessions will be invalidated on upgrade — users will need to log in again.
