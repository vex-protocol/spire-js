# @vex-chat/spire

## 1.0.4

### Patch Changes

- 0d6ba99: The `/status` endpoint now returns only `{ ok }` for regular requests. The extended response fields (`canary`, database sizing information, etc.) are now gated behind the `DEV_API_KEY` header — set `DEV_API_KEY` in your environment and pass it as `x-dev-api-key` if your monitoring needs the full response.

## 1.0.3

### Patch Changes

- fdb4807: The `/status` endpoint no longer returns `commitSha`, `dbHealthy`, `dbReady`, `latencyBudgetMs`, `metrics`, `startedAt`, `uptimeSeconds`, and `withinLatencyBudget` fields. Operators relying on those fields should source equivalent signals from their own infrastructure monitoring.

## 1.0.2

### Patch Changes

- 335818e: Bumps the `@vex-chat/crypto` dependency from `2.0.0` to `2.0.1`. No API or config changes required.
- f728d94: Optional `DEV_API_KEY` lets matching `x-dev-api-key` requests skip in-process rate limits for local load testing. Adds an npm script that drives a local Spire via `@vex-chat/libvex`. (Replaces the earlier `SPIRE_STRESS_BYPASS_KEY` / `X-Spire-Stress-Bypass` naming.)

## 1.0.1

### Patch Changes

- d262b02: Rate limits are now 10x higher across all tiers: the global per-IP limit rises from 300 to 3 000 requests per 15 minutes, the auth endpoint limit rises from 5 to 50 failed attempts per 15 minutes, and the upload limit rises from 20 to 200 requests per minute. No config changes required — limits take effect on the next server start.
- ebea78f: HTTP request logging via `morgan` has been removed from the server. Operators who relied on per-request log lines in stdout should add their own logging middleware after calling `initApp`.
- 0b7005c: Passwords are now hashed with argon2id (via a transparent on-login migration from the previous algorithm). JWT tokens are signed with a dedicated secret instead of reusing the server's persistent key pair, so all existing sessions will be invalidated on upgrade — users will need to log in again.

## 1.0.0

### Major Changes

- 7434d34: First release after a 5-year dormancy. Latest public npm was `0.8.0` (published 2021-02-03) and the repo went `private` shortly after. This cuts a new published version off the modern tree, aligned with `@vex-chat/types@2.0.0` and `@vex-chat/crypto@2.0.0`.

    Classified as **major** — not the usual pre-1.0 minor-for-breaking-changes convention. The new Zod runtime validation on every trust boundary is the deciding factor: consumers that worked against `0.8.0`'s permissive request handling will see their requests rejected by the new zod `.parse()` step when fields are missing, wrongly typed, or contain unexpected shapes. The message framing, auth layer, database layer, and docs-serving layer have all also changed substantially. Operators should treat this as a rewrite and re-integrate end-to-end rather than an in-place upgrade.

    ### Stack
    - **Pure ESM** (`type: "module"`). Previously CommonJS.
    - **Node `>=24.0.0`, npm `>=10.0.0`** engines. Previously unspecified (ran on Node 12 era).
    - **npm** enforced as the only package manager (`preinstall: npx only-allow npm`). Previously yarn.
    - **TypeScript 6.0.2** with the full strict flag set (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noPropertyAccessFromIndexSignature`, `verbatimModuleSyntax`, `isolatedModules`). Previously TypeScript 4.1 with lax settings.
    - **Runs via `node --experimental-strip-types src/run.ts`** in dev and deployment — no pre-compile step required. `dist/` is still built in CI and shipped in the tarball for consumer auditability.

    ### Web / protocol layer
    - **Express 5.2.1** (was 4.17). Major framework upgrade with new routing/middleware semantics.
    - **ws 8.20.0** directly, dropped the `express-ws` wrapper in favor of the native WebSocket upgrade path. `cookie-parser` and `atob` removed (no longer needed under Express 5 + Node 24).
    - **New: `@scalar/express-api-reference`** — interactive OpenAPI documentation viewer at `/docs` (production-gated for security).
    - **New: `@asyncapi/web-component`** — interactive AsyncAPI viewer for the WebSocket protocol at `/async-docs`.
    - **Helmet 8.1** (was 4.2). Production-only hardened CSP; relaxed CSP scoped to `/docs` and `/async-docs` only to let the interactive viewers work without loosening protection on the actual API surface.

    ### Database
    - **Kysely 0.28.16 + better-sqlite3 11.10.0** replacing **knex 0.21 + sqlite3 5.0 + mysql 2.18**. Full migration from knex's query builder to Kysely's type-safe query DSL, with better-sqlite3's synchronous binding replacing the async sqlite3 native module.
    - **MySQL support removed.** SQLite only. The old `DB_TYPE=mysql` env path and the `knex --knexfile` CLI are gone.
    - **Migrations consolidated**: the eight knex migration files from 2021 (`20210103_users.js`, `_mail.js`, `_preKeys.js`, etc.) replaced with a single Kysely schema migration (`2026-04-06_initial-schema.ts`). New installations seed from this one file; there is no upgrade path from a `0.8.0` database.

    ### Wire / validation
    - **zod 4.3.6** runtime validation on every trust boundary — every request body, query string, and WebSocket payload is parsed through a Zod schema before any logic runs. Zero `as` type assertions in the request-handling path.
    - **msgpackr 1.11.8** replacing **msgpack-lite 0.1.26**. More standards-compliant encoder/decoder; msgpack-lite's extensions were incompatible with the typed-array decoder now used in the browser SDK.
    - **`@vex-chat/types` bumped from `^0.10.18` to `2.0.0`**. Major renames throughout: `I` prefix dropped from every interface (`IBaseMsg` → `BaseMsg`, `IKeyBundle` → `KeyBundle`, etc.), schemas renamed to `XSchema` form, date fields migrated from `Date` objects to ISO 8601 strings. See the `@vex-chat/types` 2.0.0 changelog for the full migration.
    - **`@vex-chat/crypto` bumped from `^0.7.15` to `2.0.0`**. Complete nacl operation wrappers (`xSign`, `xSecretbox`, `xBoxKeyPair`, etc.) replace the earlier pattern of reaching into `nacl.*` directly from the server. `saveKeyFile`/`loadKeyFile` replaced with `encryptKeyData`/`decryptKeyData` pure functions (no I/O).

    ### Auth / crypto
    - **jsonwebtoken 9.0.3** (was 8.5). Covers CVE-2022-23529 (algorithm confusion) and related auth-layer fixes.
    - Native `node:crypto` HKDF / PBKDF2 / SHA replacing the `pbkdf2 ^3.1.1` userspace port.
    - Server crypto calls go through `@vex-chat/crypto`'s `XUtils` namespace instead of inline `tweetnacl.*`.

    ### Upload / file handling
    - **multer 2.1.1** (was 1.4.2). Major version upgrade — changed file field API semantics.
    - **file-type 22** (was 16). ESM-native upgrade.

    ### Tooling
    - **Vitest 3.2** replacing **Jest 26 + ts-jest**. Tests under `src/__tests__/` run 3x faster and integrate cleanly with the ESM module graph.
    - **ESLint 10 with `typescript-eslint@strictTypeChecked`** replacing **tslint 5.20** (long-deprecated). Added `eslint-plugin-perfectionist` for deterministic import/object sorting and `@vitest/eslint-plugin` for test-file rules, plus `eslint-plugin-n` for Node-specific best practices.
    - **Prettier 3.8** (was 1.19). Format applied repo-wide.
    - **Husky 9** + **lint-staged 16** pre-commit hooks (was Husky 3 + lint-staged 9).
    - **`@changesets/cli` 2.30** — release flow now managed via changesets instead of manual version bumps (see `AGENTS.md`, which lands alongside this release).
    - **`@onebeyond/license-checker`** license-allowlist gate in CI with a small workaround script for `@scalar/express-api-reference`'s malformed `package.json` readme field.
    - **`type-coverage` at 95%** enforced in CI.

    ### Packaging fix (important for existing `0.8.0` consumers)

    The `0.8.0` tarball shipped the server's own state files by accident — `spire.sqlite` (an actual SQLite database), the entire `emoji/` directory (user-uploaded content), and `jest.config.js`. No `files` field was set, so npm defaulted to publishing nearly the whole working tree.

    `0.9.0-rc.0` pins `files: ["dist", "src", "LICENSE"]`. The tarball now contains only the compiled output, the TypeScript source (for auditability), and the license. Database state and uploaded content stay on the deployed server, where they belong.

    ### CI / release pipeline
    - **Parallel-job `build.yml`** with a `CI OK` aggregator acting as the single required status check. Jobs: `build` (matrix: ubuntu/macos/windows), `test` (matrix: ubuntu/macos/windows — the matrix has caught real Windows-only runtime bugs), `lint`, `types`, `supply-chain`. Native module compilation (`better-sqlite3`) is what drives the cross-OS matrix on build/test.
    - **`setup-node@v6`** with `cache: npm` and `node-version-file: .tool-versions`. Dropped the `jdx/mise-action` step in CI; `mise.toml` stays for local dev parity.
    - **`release.yml`** uses `changesets/action` to open version-packages PRs and publish to npm with **provenance attestation** (`--provenance`, `id-token: write`). SBOM generated via `@cyclonedx/cyclonedx-npm` and uploaded as an artifact on every successful publish.
    - **Deploy-hook moved to `release.yml`.** Previously in `build.yml` firing on every master push, which meant unrelated commits (CI tweaks, docs) triggered production deploys. Now deploy only fires after a successful `changesets/action` publish — tight coupling between "version went out" and "production updates".
    - **`auto-changeset.yml`** runs a Claude prompt on every human PR that reads `AGENTS.md`, builds the PR's current source, downloads the latest published tarball, and byte-diffs the two to decide whether the PR is user-visible. Biases hard toward empty changesets for CI/docs/config-only PRs to avoid no-op releases.
    - **CodeQL v4.35.1** + **OSSF Scorecard v2.4.3** + **Socket.dev supply-chain scanning** (fork-gated) + **step-security/harden-runner** on every job.
    - **Dependabot** grouped: one weekly PR for all github-actions bumps, one each for production and development npm deps.
    - **`npm-package-json-lint`** gate enforces exact version pins (no `^` ranges) across all dependencies and devDependencies.

    ### AGENTS.md

    A new `AGENTS.md` lands alongside this release documenting the release flow, the `NEVER` / `SAFE` lists for agents and humans, the published-tarball footprint, dependabot exemption policy, and required secrets. Future agent-authored changesets read this file first as the source of truth on what counts as user-visible.
