---
"@vex-chat/spire": patch
---

HTTP request logging via `morgan` is back. UUIDs in request URLs are replaced with `[uuid]` before the log line is written, so per-request traces no longer leak user or resource identifiers to stdout. No config changes required.
