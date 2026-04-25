#!/usr/bin/env node
/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Generates keys for `SPIRE_FIPS=true` (P-256) Spire: PKCS#8 ECDSA private
 * in hex for `SPK` plus a separate random `JWT_SECRET`.
 *
 * Do **not** use `gen-spk.js` for FIPS: that script produces 64-byte Ed25519
 * `SPK` for tweetnacl mode. FIPS Spire uses `xSignKeyPairFromSecretAsync` and
 * expects a PKCS#8 P-256 key body (longer hex).
 *
 * Usage:
 *   node scripts/gen-spk-fips.js
 *   node scripts/gen-spk-fips.js --raw
 */

import { randomBytes, webcrypto } from "node:crypto";

const raw = process.argv.includes("--raw") || process.argv.includes("-r");
const subtle = webcrypto.subtle;
const keyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
);
const pkcs8 = await subtle.exportKey("pkcs8", keyPair.privateKey);
const spk = Buffer.from(pkcs8).toString("hex");
const jwtSecret = randomBytes(32).toString("hex");

if (raw) {
    console.log(spk);
    console.log(jwtSecret);
} else {
    console.log(
        "Use with SPIRE_FIPS=true. SPK = PKCS#8 (P-256) hex; not compatible with gen-spk.js (Ed25519).",
    );
    console.log(`SPK="${spk}"`);
    console.log(`JWT_SECRET="${jwtSecret}"`);
}
