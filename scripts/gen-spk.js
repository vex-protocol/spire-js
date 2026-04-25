#!/usr/bin/env node
/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Generates cryptographic keys for Spire's .env in **tweetnacl** (default) mode:
 *
 *   SPK        — 64-byte Ed25519 secret (hex). NaCl / tweetnacl server signing.
 *   JWT_SECRET — 32-byte random secret (hex). Used as the HMAC key for JWTs.
 *
 * For **FIPS** (`SPIRE_FIPS=true`), use `node scripts/gen-spk-fips.js` instead
 * (P-256 PKCS#8 `SPK` — a different size and format).
 *
 * These MUST be separate keys so compromise of one doesn't affect the other.
 *
 * Usage:
 *   node scripts/gen-spk.js           # SPK="..." + JWT_SECRET="..."
 *   node scripts/gen-spk.js --raw     # hex only, no wrappers
 */

import { randomBytes } from "node:crypto";

import nacl from "tweetnacl";

const raw = process.argv.includes("--raw") || process.argv.includes("-r");

const pair = nacl.sign.keyPair();
const spk = Buffer.from(pair.secretKey).toString("hex");
const jwtSecret = randomBytes(32).toString("hex");

if (raw) {
    console.log(spk);
    console.log(jwtSecret);
} else {
    console.log(`SPK="${spk}"`);
    console.log(`JWT_SECRET="${jwtSecret}"`);
}
