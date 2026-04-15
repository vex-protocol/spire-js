---
"@vex-chat/spire": patch
---

HTTP request logging via `morgan` has been removed from the server. Operators who relied on per-request log lines in stdout should add their own logging middleware after calling `initApp`.
