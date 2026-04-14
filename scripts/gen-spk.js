#!/usr/bin/env node
/**
 * Generates cryptographic keys for Spire's .env file:
 *
 *   SPK        — 64-byte Ed25519 secret (hex). Used for NaCl server signing.
 *   JWT_SECRET — 32-byte random secret (hex). Used as the HMAC key for JWTs.
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
