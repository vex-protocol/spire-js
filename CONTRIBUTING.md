# Contributing

## Contributor License Agreement (CLA)

**Before we merge a non-trivial contribution from someone who is not already covered by a corporate agreement**, that person must agree to the [**Contributor License Agreement**](./CLA.md) (individual).

Typical ways this is handled:

- **[cla-bot](https://github.com/apps/cla-bot)** (recommended): the [`.clabot`](./.clabot) file lists GitHub usernames that have a CLA on file. Install the GitHub App on this repo (org settings → GitHub Apps), then add approved usernames to `contributors`. When a PR needs a CLA, **cla-bot** posts a comment with links to [CLA.md](./CLA.md) and **[vex.wtf/cla](https://vex.wtf/cla)** — use that link from the PR (the main site does not advertise this flow in the nav). Maintainers use **Admin → CLA approvals** on vex.wtf when signed in. Re-check with **`@cla-bot check`** on the PR.
- **GitHub CLA Assistant** (or similar): alternative if you prefer that flow.
- **Manual**: maintainers record that the contributor commented on the PR (e.g. “I agree to the CLA”) or returned a signed copy, consistent with your counsel’s guidance.

**Before the first external PR:** add maintainer GitHub usernames to `.clabot` → `contributors` so your own PRs pass the check. Optionally make the **`cla-bot`** / **`verification/cla-signed`** status a required check in branch protection.

Trivial changes (e.g. typo fixes) are often handled under the same policy your lawyers prefer—align this section with them.

## Licensing overview

See [**LICENSING.md**](./LICENSING.md) for the default **AGPL-3.0-or-later** terms and **commercial licensing** contact information.

## Copyright headers

New source files under `src/`, `scripts/`, and `services/` should include the standard header (see any existing `.ts` / `.js` file).

- **Check (also runs in CI):** `npm run copyright:check`
- **Apply missing headers:** `npm run copyright:apply`

From the **vex-protocol** monorepo root, run all three repos with: `node scripts/add-copyright-headers.mjs` (add) or `node scripts/add-copyright-headers.mjs --check`.

## Development

See the [README](./README.md) (build, test, lint) and [AGENTS.md](./AGENTS.md) (releases and changesets).
