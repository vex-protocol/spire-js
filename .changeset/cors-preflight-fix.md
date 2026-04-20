---
"@vex-chat/spire": patch
---

CORS middleware now runs before helmet and auth, so browser preflight (`OPTIONS`) requests receive `Access-Control-*` headers even for unauthenticated routes. Browser clients (web, Tauri, Capacitor) that were being blocked by CORS errors should work without any config changes. The allowed-methods list is now explicit: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`.
