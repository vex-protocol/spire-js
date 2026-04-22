# AGENTS.md

Guardrails for AI agents (and humans pairing with them) working in this repo.
The release pipeline is fully automated via [Changesets](https://github.com/changesets/changesets) and deploys via a webhook fired from the release workflow. Agents that try to "help" by hand-editing the things the pipeline generates — or by bypassing the changesets flow entirely — WILL break the flow. Read this before touching anything in the lists below.

## Release flow (how it actually works)

Spire is deployed as a published npm package **and** via a webhook POST from the release workflow. The full loop:

1. A feature branch lands a code change **and** a changeset file in `.changeset/<slug>.md`. The changeset file declares the semver bump (`patch`/`minor`/`major`) and a user-facing summary — nothing else.
2. The changeset file is written either:
    - **Automatically** by `.github/workflows/auto-changeset.yml`, which runs Claude on every human PR and generates a changeset if one is missing, **or**
    - **Manually** by a human in `.changeset/<slug>.md` if they want to control the wording.
    - **Dependabot PRs are exempt** — they merge without a changeset and get bundled into the next human-authored release. See "Dependabot PRs" below.
3. PR merges to `master`.
4. `.github/workflows/release.yml` runs `changesets/action`. If there are pending changesets, it opens a `chore: version packages` PR that:
    - bumps `package.json` version
    - rewrites `CHANGELOG.md`
    - deletes the consumed `.changeset/*.md` files
5. Merging the `chore: version packages` PR re-runs `release.yml`, which publishes to npm with provenance.
6. **After a successful publish**, the `deploy-hook` job in `release.yml` fires — POSTs to `DEPLOY_HOOK_URL` with bearer auth from `DEPLOY_HOOK_SECRET`. This is spire's production deploy trigger.

**The agent's job in all of this is step 1 and only step 1.** Everything after that is the action's job.

### Why deploy is coupled to publish

The deploy-hook used to fire on every master push from `build.yml`. That meant non-user-visible commits (CI tweaks, docs, config changes) triggered production deploys. Now deploy is gated on `changesets/action` publishing a new version. Exactly one deploy per published version, no extras.

## NEVER do these (locally OR in CI)

- ❌ Run `npx changeset version` / `changeset version`. That's the release action's job. Running it locally bakes version bumps and CHANGELOG rewrites into feature commits, which then collide with (or skip) the release PR.
- ❌ Hand-edit `package.json`'s `version` field. The release action owns it.
- ❌ Hand-edit `CHANGELOG.md`. It is regenerated from changeset files. Any manual edit will be overwritten or create a conflict on the next release.
- ❌ Run `npx changeset publish`. Publishing only happens from `release.yml` on `master`.
- ❌ Set `"private": true` back in `package.json`. Doing so blocks publish and breaks the release flow.
- ❌ POST to the deploy-hook URL manually. The only caller is `release.yml`'s `deploy-hook` job, gated on a successful publish.
- ❌ Run `npx changeset pre enter` / `pre exit`. Pre-release mode is a deliberate choice that flips the whole release flow; if you think you need it, stop and ask the human.
- ❌ Delete files from `.changeset/` unless you are removing a changeset you just wrote in error in the same session. Consumed changesets are deleted by `changeset version`; deleting them any other way drops the corresponding CHANGELOG entry.

## SAFE to do

- ✅ Create a new `.changeset/<short-slug>.md` with frontmatter:

    ```markdown
    ---
    "@vex-chat/spire": patch
    ---

    One to three sentences, operator-facing, describing impact not implementation.
    ```

    Use `patch` for bugfixes, `minor` for backward-compatible features, `major` for breaking changes.

- ✅ Edit source code in `src/`, scripts, workflows, configs, tests, README, and this file.
- ✅ Run `npm run build`, `npm run lint`, `npm test`, `npm audit`, `npx type-coverage` — all read-only w.r.t. the release flow.
- ✅ Run `npm start` (which uses `node --experimental-strip-types src/run.ts`) to boot the server locally.

## What ships in the npm tarball

The published `@vex-chat/spire` tarball contains only:

- `dist/` — compiled JS + `.d.ts` produced by `tsc`
- `src/` — shipped for operator auditability and `--experimental-strip-types` runtime
- `package.json`, `README.md`, `LICENSE`, `CHANGELOG.md` (always included by npm regardless of `files`)

Anything else you edit — `.github/`, tsconfig, eslint config, `src/__tests__/**` (vitest unit tests), `vitest.config.ts`, `mise.toml`, `.tool-versions`, `AGENTS.md`, `CHANGELOG.md` itself, `scripts/` (dev utilities), `services/` (sibling service helpers), `public/` (static docs assets served by the running server, not shipped on npm) — is NOT in the tarball's footprint and is NOT user-visible. PRs touching only those files should ship an **empty changeset** (`---\n---\n`) so the release flow records "nothing to publish."

## Deliberate shape choices (don't "fix" these)

- **No `main`, `types`, `exports`, or `bin` field.** Spire is published as a "box of files" — operators install it to get the source and compiled output, and run it how they want (`node --experimental-strip-types node_modules/@vex-chat/spire/src/run.ts` or by cloning the repo). This is intentional. Don't add library entry points.
- \*\*`build.yml` runs `build` and `test` in `checks` (ubuntu), plus two Docker stress jobs: `stress (tweetnacl)` — `gen-spk.js`, default server profile — and `stress (FIPS)` — `gen-spk-fips.js`, `SPIRE_FIPS=true`, asserts `GET /status` → `fips`. Both build the same image and run `npm run stress:cli` against `127.0.0.1:16777` (informational). The repo used to run a multi-OS matrix for native edge cases; if you reintroduce that, don’t drop coverage without reason.
- **Running via `node --experimental-strip-types src/run.ts`** in dev and prod — no pre-compile step required. `dist/` is still built in CI as a sanity check and shipped in the tarball, but it's not the runtime entry point.

## Generated / machine-owned files

Treat these as **outputs**, not sources. The source of truth is listed in parentheses.

| File                     | Source                    | Written by               |
| ------------------------ | ------------------------- | ------------------------ |
| `package.json` `version` | changeset bumps           | `changesets/action`      |
| `CHANGELOG.md`           | `.changeset/*.md`         | `changesets/action`      |
| `package-lock.json`      | `package.json` + registry | `npm install` / `npm ci` |
| `dist/`                  | `src/`                    | `npm run build`          |
| `docs/`                  | `src/` + TSDoc comments   | `npx typedoc` (local)    |

## Dependabot PRs

Dependabot PRs are deliberately treated as second-class citizens by the release flow:

- `build.yml`'s `Check for changeset` step skips when `github.actor == 'dependabot[bot]'`, so dependabot PRs don't fail CI on the missing-changeset check.
- `auto-changeset.yml` does not run on bot-authored PRs (the `user.type != 'Bot'` filter).
- Merged dependabot PRs land on master with **no corresponding `.changeset/*.md` file**, so `release.yml` sees nothing to process for that merge alone. The dep bumps get silently bundled into the next human-authored release whenever the next real changeset ships — and because spire's deploy is gated on a successful publish, **no deploy fires from a dependabot merge**. That's intentional.

**Why not auto-generate one?** Three stacked GitHub constraints make it not worth the complexity for this project:

1. Dependabot PRs can't access regular repository secrets (including `ANTHROPIC_API_KEY`) — dependabot secrets are a separate bucket. Claude can't run on them.
2. Dependabot PRs get a read-only `GITHUB_TOKEN`, so a sibling workflow can't write a changeset back to the PR branch without a PAT.
3. Even a successful PAT-authored push would need to re-trigger `build.yml` on the new head sha, which requires the push to _also_ be authored by a PAT — otherwise branch protection blocks the merge.

**If a dep bump deserves its own CHANGELOG entry** (e.g., an `express` major upgrade that changes request handling, or a `kysely` bump that changes query semantics), write a manual `.changeset/<slug>.md` as an extra commit on the dependabot PR before merging. That's the one case where hand-writing a changeset is expected.

## If you're unsure

- Want to ship a change? Edit code, stop. Either write one `.changeset/*.md` file or let the auto-changeset workflow write it on the PR.
- A CI check is failing with "missing changeset"? Add a changeset file. Do not bump the version to silence the check.
- Did you edit only workflows, configs, tests, or docs? Add an **empty changeset** (`---\n---\n`) to tell the release flow there's nothing to publish (and therefore nothing to deploy).
- You think the release is broken? Read `.github/workflows/release.yml` and `.github/workflows/auto-changeset.yml` end-to-end before changing anything, and prefer asking the human over "fixing" the workflow.
- The deploy hook fired for a release you didn't expect? Check whether `changesets/action` actually published — the hook only runs when `needs.release.outputs.published == 'true'`.

## Required secrets (informational)

- `NPM_TOKEN` — npm publish token for the `@vex-chat` scope
- `ANTHROPIC_API_KEY` — used by `auto-changeset.yml` to generate changesets
- `SOCKET_API_KEY` — Socket.dev supply-chain scan in `build.yml`
- `DEPLOY_HOOK_URL` — URL of the production deploy webhook (release.yml only)
- `DEPLOY_HOOK_SECRET` — bearer token for the deploy webhook (release.yml only)
- `GITHUB_TOKEN` — provided automatically
