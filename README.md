# @vex-chat/spire

[![npm](https://img.shields.io/npm/v/@vex-chat/spire?style=flat-square&color=cb3837&logo=npm)](https://www.npmjs.com/package/@vex-chat/spire)
[![CI](https://img.shields.io/github/actions/workflow/status/vex-protocol/spire-js/build.yml?branch=master&style=flat-square&logo=github&label=CI)](https://github.com/vex-protocol/spire-js/actions/workflows/build.yml)
[![Released](https://img.shields.io/github/release-date/vex-protocol/spire-js?style=flat-square&label=released)](https://github.com/vex-protocol/spire-js/releases)
[![License](https://img.shields.io/npm/l/@vex-chat/spire?style=flat-square&color=blue)](./LICENSE)
[![Type Coverage](https://img.shields.io/badge/dynamic/json?style=flat-square&label=type-coverage&prefix=%E2%89%A5&suffix=%25&query=$.typeCoverage.atLeast&url=https://raw.githubusercontent.com/vex-protocol/spire-js/master/package.json&color=3178c6&logo=typescript)](https://github.com/plantain-00/type-coverage)
[![Node](https://img.shields.io/node/v/@vex-chat/spire?style=flat-square&color=339933&logo=nodedotjs)](./package.json)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/vex-protocol/spire-js?style=flat-square&label=Scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/vex-protocol/spire-js)
[![Socket](https://socket.dev/api/badge/npm/package/@vex-chat/spire)](https://socket.dev/npm/package/@vex-chat/spire)

Reference server implementation for the [Vex](https://vex.wtf) protocol.

## What's in the box

- **REST API** (Express 5) for full e2e messaging including auth, registration, users, servers, channels, invites, and file upload.

## Install

Or clone the repo:

```sh
git clone git@github.com:vex-protocol/spire-js
cd spire-js
npm ci
```

## Running the server (Docker)

From a clone, with Docker and Docker Compose installed:

```sh
cp .env.example .env
# set SPK, JWT_SECRET, DB_TYPE, SPIRE_FIPS, … (see Configuration)
docker compose up --build
```

**Crypto mode (tweetnacl vs FIPS):** `SPIRE_FIPS` in `.env` selects the server profile. It must match how you generated `SPK` — **`npm run gen-spk`** (Ed25519) for tweetnacl, or **`npm run gen-spk-fips`** (P-256) with **`SPIRE_FIPS=true`**. You can override for one run without editing `.env`: `SPIRE_FIPS=true docker compose up` (or `=false`).

Compose builds the image from this repo’s `Dockerfile`, starts Spire with a persistent **`spire-data`** volume mounted at `/data` (SQLite + `files/`, `avatars/`, `emoji/`), and fronts it with **nginx** on host **port 16777** (see `ports` in `docker-compose.yml`). Spire itself listens on **16777** inside the `internal` network (same for tweetnacl and FIPS — `GET /status` reports the crypto profile). Nginx and the health check use `deploy/resolve-spire-listen-port.sh` to match. Use **http://127.0.0.1:16777** for HTTP and WebSocket.

## Running without Docker

For local development or if you installed from npm, Spire runs with `node --experimental-strip-types` (no separate compile step):

```sh
npm start
# or: node --experimental-strip-types src/run.ts
```

From an npm install, sources live under `node_modules/@vex-chat/spire/src/`:

```sh
node --experimental-strip-types node_modules/@vex-chat/spire/src/run.ts
```

## Configuration

Spire reads configuration from environment variables. **Docker Compose:** put them in a `.env` file next to `docker-compose.yml` (the `env_file` entry injects them into the container). **Bare Node:** `dotenv` loads `.env` from the process working directory when you run `src/run.ts`.

### Required

| Variable     | Description                                                                                                                                                                                               |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SPK`        | Server private key, hex-encoded. **tweetnacl:** `npm run gen-spk` (Ed25519). **FIPS:** `npm run gen-spk-fips` and set `SPIRE_FIPS=true` (P-256 PKCS#8). Each command prints `SPK` and `JWT_SECRET` lines. |
| `JWT_SECRET` | Hex or string used as the **HMAC secret for JWTs** — **required** and must be **separate from `SPK`**. `npm run gen-spk` emits a dedicated value; do not reuse `SPK` here.                                |
| `DB_TYPE`    | `sqlite3` or `sqlite3mem`. All values use **SQLite** via `better-sqlite3` (file or `:memory:`).                                                                                                           |

### Optional

| Variable       | Default    | Description                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SPIRE_FIPS`   | _falsy_    | If `true` or `1`, run the **FIPS** profile (P-256, Web Crypto). `SPK` must come from `npm run gen-spk-fips`, not `gen-spk`. Any other value uses **tweetnacl** (Ed25519) and `gen-spk`. In Docker Compose, the service passes `SPIRE_FIPS=${SPIRE_FIPS:-false}` so the shell or `.env` can set the mode.                                                                                               |
| `API_PORT`     | (see text) | If unset, Spire listens on **16777** (all crypto profiles; use `GET /status` to see which). In Docker, nginx and the image healthcheck use `deploy/resolve-spire-listen-port.sh` to follow the same rule. Set explicitly to override.                                                                                                                                                                  |
| `NODE_ENV`     | _(unset)_  | Set to `production` to disable interactive `/docs` / `/async-docs`. If unset or any other value, doc viewers are mounted. `helmet()` runs in all modes.                                                                                                                                                                                                                                                |
| `CORS_ORIGINS` | _(empty)_  | Comma-separated allowed `Origin` values. If set, only those origins may use credentialed browser requests. If unset, Spire **reflects the request `Origin`** so self-hosted Spire and arbitrary app origins (Tauri, localhost, etc.) work without configuration — appropriate for bearer-token APIs; set an allowlist if you need to restrict which sites may call your instance from users' browsers. |
| `DEV_API_KEY`  | _(empty)_  | When set, requests that send header `x-dev-api-key` with the same value (constant-time compare) **skip in-process rate limiters**. The same gate enables **`GET /status/process`** (404 without a valid key): a small JSON snapshot of the Spire Node process (PID, uptime, `memoryUsage`, cumulative `resourceUsage`, WebSocket client count). Dev / load-testing only — never set in production.     |
| `CANARY`       | _(unset)_  |                                                                                                                                                                                                                                                                                                                                                                                                        |

### Sample `.env`

```sh
# Run `npm run gen-spk` and paste the two lines it prints (SPK + JWT_SECRET).
SPK=a1b2c3...
JWT_SECRET=d4e5f6...
DB_TYPE=sqlite
# CANARY=true
# API_PORT=        # unset = 16777 unless you override
NODE_ENV=production
```

## Development

```sh
npm run build         # tsc (sanity check — runtime uses --experimental-strip-types)
npm run lint          # eslint strictTypeChecked
npm run lint:fix      # eslint --fix
npm run format        # prettier --write
npm run format:check
npm test              # vitest run
npx type-coverage     # type-coverage (≥95%)
```

See [AGENTS.md](./AGENTS.md) for the release flow (changesets → publish → deploy-hook) and the rules for writing changesets.

Contributions from outside contributors should follow [CONTRIBUTING.md](./CONTRIBUTING.md) (including the [CLA](./CLA.md)).

## License

Open source default: **[AGPL-3.0](./LICENSE)** (full text; see `package.json` for SPDX). Commercial licenses from **Vex Heavy Industries LLC**: [**LICENSE-COMMERCIAL**](./LICENSE-COMMERCIAL), [**LICENSING.md**](./LICENSING.md), [vex.wtf](https://vex.wtf/licensing).
