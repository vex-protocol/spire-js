---
"@vex-chat/spire": minor
---

Set `SPIRE_FIPS=1` (or `SPIRE_FIPS=true`) to run Spire in FIPS-compliant mode. In FIPS mode the server uses P-256 (Web Crypto `subtle`) instead of tweetnacl for all signing operations, and `GET /status` now returns a `cryptoProfile` field (`"fips"` or `"tweetnacl"`) so monitoring can confirm the active crypto backend. A `postinstall` hook now rebuilds `better-sqlite3` from source automatically, removing the need to run `npm rebuild better-sqlite3` manually after install on glibc-based systems.
