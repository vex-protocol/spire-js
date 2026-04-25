/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { getCryptoProfile, xSignOpen, xSignOpenAsync } from "@vex-chat/crypto";

/**
 * Ed25519 detached-verify open: sync on tweetnacl, async for FIPS (Web Crypto).
 */
export async function spireXSignOpenAsync(
    signedMessage: Uint8Array,
    publicKey: Uint8Array,
): Promise<null | Uint8Array> {
    if (getCryptoProfile() === "fips") {
        return xSignOpenAsync(signedMessage, publicKey);
    }
    return xSignOpen(signedMessage, publicKey);
}
