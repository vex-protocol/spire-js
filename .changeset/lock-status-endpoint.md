---
"@vex-chat/spire": patch
---

The `/status` endpoint now returns only `{ ok }` for regular requests. The extended response fields (`canary`, database sizing information, etc.) are now gated behind the `DEV_API_KEY` header — set `DEV_API_KEY` in your environment and pass it as `x-dev-api-key` if your monitoring needs the full response.
