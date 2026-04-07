#!/usr/bin/env node
/**
 * Prints a cryptographically secure SPK for .env.
 *
 * Spire uses this value in two ways:
 *   - Decode hex → 64-byte Ed25519 secret for nacl.sign.keyPair.fromSecretKey
 *   - Same string is passed to jsonwebtoken as the HMAC secret
 *
 * It must be lowercase hex encoding of exactly 64 bytes (128 hex chars).
 *
 * Usage:
 *   node scripts/gen-spk.js           # SPK="..."  (paste into .env)
 *   node scripts/gen-spk.js --raw     # hex only, no wrapper
 */

import nacl from "tweetnacl";

const raw = process.argv.includes("--raw") || process.argv.includes("-r");

const pair = nacl.sign.keyPair();
const spk = Buffer.from(pair.secretKey).toString("hex");

if (raw) {
    console.log(spk);
} else {
    console.log(`SPK="${spk}"`);
}
