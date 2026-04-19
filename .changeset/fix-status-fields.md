---
"@vex-chat/spire": patch
---

The `/status` endpoint no longer returns `commitSha`, `dbHealthy`, `dbReady`, `latencyBudgetMs`, `metrics`, `startedAt`, `uptimeSeconds`, and `withinLatencyBudget` fields. Operators relying on those fields should source equivalent signals from their own infrastructure monitoring.
