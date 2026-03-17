/**
 * NaCl-compatible Ed25519 operations using @noble/curves.
 * Drop-in replacements for the tweetnacl functions used in spire.
 */
// tslint:disable-next-line:no-submodule-imports
import { ed25519 } from "@noble/curves/ed25519";

export interface ISignKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}

/**
 * Reconstructs a signing key pair from a 64-byte TweetNaCl secret key
 * (first 32 bytes = seed, last 32 bytes = public key).
 * Equivalent to `nacl.sign.keyPair.fromSecretKey(sk)`.
 */
export function keyPairFromSecretKey(sk: Uint8Array): ISignKeyPair {
    const seed = sk.subarray(0, 32);
    const publicKey = ed25519.getPublicKey(seed);
    return { publicKey, secretKey: sk };
}

/**
 * Verifies a NaCl-signed message (64-byte signature prepended to message)
 * and returns the original message, or null if verification fails.
 * Equivalent to `nacl.sign.open(signedMessage, publicKey)`.
 */
export function signOpen(
    signedMessage: Uint8Array,
    publicKey: Uint8Array
): Uint8Array | null {
    if (signedMessage.length < 64) {
        return null;
    }
    const signature = signedMessage.subarray(0, 64);
    const message = signedMessage.slice(64);
    try {
        return ed25519.verify(signature, message, publicKey) ? message : null;
    } catch {
        return null;
    }
}
