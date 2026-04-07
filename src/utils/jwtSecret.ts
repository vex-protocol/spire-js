/**
 * Returns the JWT signing secret.
 *
 * Prefers JWT_SECRET (dedicated HMAC key) over SPK (NaCl server signing key).
 * Using SPK for JWT HMAC is a key-reuse concern flagged in auth-comparison.md.
 * Fall back to SPK for backward compat with existing deployments.
 */
export function getJwtSecret(): string {
    const secret = process.env.JWT_SECRET ?? process.env.SPK;
    if (!secret) {
        throw new Error(
            "Neither JWT_SECRET nor SPK is set. " +
                "Set JWT_SECRET (preferred) or SPK in your environment.",
        );
    }
    return secret;
}
