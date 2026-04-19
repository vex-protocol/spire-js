# Contributing

## Contributor License Agreement (CLA)

**Before we merge a non-trivial contribution from someone who is not already covered by a corporate agreement**, that person must agree to the [**Contributor License Agreement**](./CLA.md) (individual).

Typical ways this is handled:

- **GitHub CLA Assistant** (or similar): configure the bot so contributors sign electronically when they open a pull request.
- **Manual**: maintainers record that the contributor commented on the PR (e.g. “I agree to the CLA”) or returned a signed copy, consistent with your counsel’s guidance.

Trivial changes (e.g. typo fixes) are often handled under the same policy your lawyers prefer—align this section with them.

## Licensing overview

See [**LICENSING.md**](./LICENSING.md) for the default **AGPL-3.0-or-later** terms and **commercial licensing** contact information.

## Copyright headers

New source files under `src/`, `scripts/`, and `services/` should include the standard header (see any existing `.ts` / `.js` file). From the **vex-protocol** workspace root, you can (re)apply headers with:

`node scripts/add-copyright-headers.mjs spire-js`

## Development

See the [README](./README.md) (build, test, lint) and [AGENTS.md](./AGENTS.md) (releases and changesets).
