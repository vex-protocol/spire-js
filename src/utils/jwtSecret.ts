/**
 * Returns the dedicated JWT HMAC signing secret.
 *
 * This MUST be a separate key from SPK (the Ed25519 server signing key)
 * so that compromise of one does not affect the other.
 */
export function getJwtSecret(): string {
    const secret = process.env["JWT_SECRET"];
    if (!secret) {
        throw new Error(
            "JWT_SECRET is not set. Generate one with: node scripts/gen-spk.js",
        );
    }
    return secret;
}
