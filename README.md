# @vex-chat/spire

[![npm](https://img.shields.io/npm/v/@vex-chat/spire?style=flat-square&color=cb3837&logo=npm)](https://www.npmjs.com/package/@vex-chat/spire)
[![CI](https://img.shields.io/github/actions/workflow/status/vex-protocol/spire/build.yml?branch=master&style=flat-square&logo=github&label=CI)](https://github.com/vex-protocol/spire/actions/workflows/build.yml)
[![Released](https://img.shields.io/github/release-date/vex-protocol/spire?style=flat-square&label=released)](https://github.com/vex-protocol/spire/releases)
[![License](https://img.shields.io/npm/l/@vex-chat/spire?style=flat-square&color=blue)](./LICENSE)
[![Type Coverage](https://img.shields.io/badge/dynamic/json?style=flat-square&label=type-coverage&prefix=%E2%89%A5&suffix=%25&query=$.typeCoverage.atLeast&url=https://raw.githubusercontent.com/vex-protocol/spire/master/package.json&color=3178c6&logo=typescript)](https://github.com/plantain-00/type-coverage)
[![Node](https://img.shields.io/node/v/@vex-chat/spire?style=flat-square&color=339933&logo=nodedotjs)](./package.json)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/vex-protocol/spire-js?style=flat-square&label=Scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/vex-protocol/spire-js)
[![Socket](https://socket.dev/api/badge/npm/package/@vex-chat/spire)](https://socket.dev/npm/package/@vex-chat/spire)

Reference server implementation for the [Vex](https://vex.wtf) encrypted chat platform. NodeJS + SQLite + TypeScript, running the wire protocol defined in [@vex-chat/types](https://github.com/vex-protocol/types-js).

## What's in the box

- **REST API** (Express 5) for auth, registration, users, servers, channels, invites, and file upload.
- **WebSocket server** (native `ws`) for real-time messaging, presence, and push notifications. Frames are msgpack-encoded per the AsyncAPI spec in `@vex-chat/types`.
- **SQLite persistence** via Kysely + better-sqlite3. Single-file DB, zero external services.
- **Runtime validation** on every trust boundary: every request body, query string, and WebSocket payload is parsed through a Zod schema before any logic runs.
- **Interactive docs** — [Scalar](https://scalar.com) at `/docs` for the OpenAPI spec, the [AsyncAPI web component](https://www.asyncapi.com) at `/async-docs` for the WebSocket protocol. Both production-gated for security.
- **Authentication** via `@vex-chat/crypto` signing keys plus JWT session tokens. Password hashing via native `node:crypto` PBKDF2.

## Install

From public npm:

```sh
npm install @vex-chat/spire
```

Or clone the repo:

```sh
git clone git@github.com:vex-protocol/spire
cd spire
npm ci
```

## Running the server

Spire runs directly from source via `node --experimental-strip-types` — no pre-compile step needed in dev or prod. From a clone:

```sh
npm start
```

Or equivalently:

```sh
node --experimental-strip-types src/run.ts
```

From an npm install, the source ships in the tarball under `node_modules/@vex-chat/spire/src/`, so you can run it directly:

```sh
node --experimental-strip-types node_modules/@vex-chat/spire/src/run.ts
```

## Configuration

Spire reads configuration from environment variables. Use a `.env` file at the repo root (or wherever you run it from) — `dotenv` picks it up automatically.

### Required

| Variable  | Description                                                                                                                                                                                                       |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SPK`     | Server private key, hex-encoded. Generate one with `npm run gen-spk`. Used for server identity signing and as the default JWT secret if `JWT_SECRET` isn't set.                                                   |
| `DB_TYPE` | `sqlite`, `sqlite3`, or `sqlite3mem`. Controls database backend. `sqlite3mem` runs an in-memory database useful for tests. (MySQL support was removed in `1.0.0`; operators on older deploys should migrate out.) |
| `CANARY`  | `true` to enable canary mode (runs extra runtime assertions). `false` for standard production.                                                                                                                    |

### Optional

| Variable     | Default       | Description                                                                                        |
| ------------ | ------------- | -------------------------------------------------------------------------------------------------- |
| `API_PORT`   | `16777`       | Port for the REST API and WebSocket server.                                                        |
| `NODE_ENV`   | `development` | `production` enables hardened Helmet CSP and disables interactive `/docs` / `/async-docs` viewers. |
| `JWT_SECRET` | `SPK`         | Override the JWT signing secret. Falls back to `SPK` if unset.                                     |

### Sample `.env`

```sh
SPK=a1b2c3...        # generate with `npm run gen-spk`
DB_TYPE=sqlite
CANARY=false
API_PORT=16777
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
npm run license:check # license allowlist gate
```

See [AGENTS.md](./AGENTS.md) for the release flow (changesets → publish → deploy-hook) and the rules for writing changesets.

## License

[AGPL-3.0-or-later](./LICENSE)
