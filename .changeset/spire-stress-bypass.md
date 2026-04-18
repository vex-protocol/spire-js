---
"@vex-chat/spire": patch
---

Optional `DEV_API_KEY` lets matching `x-dev-api-key` requests skip in-process rate limits for local load testing. Adds an npm script that drives a local Spire via `@vex-chat/libvex`. (Replaces the earlier `SPIRE_STRESS_BYPASS_KEY` / `X-Spire-Stress-Bypass` naming.)
