---
"@vex-chat/spire": patch
---

Rate limits are now 10x higher across all tiers: the global per-IP limit rises from 300 to 3 000 requests per 15 minutes, the auth endpoint limit rises from 5 to 50 failed attempts per 15 minutes, and the upload limit rises from 20 to 200 requests per minute. No config changes required — limits take effect on the next server start.
