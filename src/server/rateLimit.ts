import type { Request } from "express";

import { timingSafeEqual } from "node:crypto";

import rateLimit, { ipKeyGenerator } from "express-rate-limit";

/** HTTP header carrying the dev API key (must match {@link process.env.DEV_API_KEY}). */
export const DEV_API_KEY_HEADER = "x-dev-api-key";

/**
 * When `DEV_API_KEY` is set in the environment, any request whose
 * `x-dev-api-key` header matches (constant-time) skips all in-process rate
 * limiters. Dev / load-testing escape hatch only — never set in production.
 * (Future: first-class API keys with scopes may reuse this header name.)
 */
export function devApiKeySkipsRateLimits(req: Request): boolean {
    const configured = process.env["DEV_API_KEY"]?.trim() ?? "";
    if (configured.length === 0) {
        return false;
    }
    const presented = req.get(DEV_API_KEY_HEADER);
    if (!presented || presented.length !== configured.length) {
        return false;
    }
    try {
        return timingSafeEqual(
            Buffer.from(presented, "utf8"),
            Buffer.from(configured, "utf8"),
        );
    } catch {
        return false;
    }
}

/**
 * Rate limiting middleware.
 *
 * Three tiers matching CWE-307 (brute-force auth), CWE-400 / CWE-770
 * (unrestricted resource consumption), and OWASP API4:2023:
 *
 * - `globalLimiter` — baseline per-IP limit across every route. Wide
 *   enough to not bother normal clients, tight enough to shield the
 *   server from a single-host flood.
 * - `authLimiter` — strict per-IP limit on auth endpoints (register,
 *   login, device challenge). `skipSuccessfulRequests` means only the
 *   failed attempts count, so a correct login doesn't eat the budget.
 * - `uploadLimiter` — upload-specific limit applied before multer,
 *   so multer never even parses a request that's over quota.
 *
 * All three use `ipKeyGenerator` from `express-rate-limit@7.4+` to
 * bucket IPv4 and IPv4-mapped IPv6 correctly (CVE-2026-30827 — older
 * versions silently collapsed all IPv4-mapped IPv6 addresses into
 * one bucket, which let attackers bypass the limiter).
 *
 * `trust proxy` must be set on the Express app (see Spire.ts) so
 * `req.ip` returns the real client address, not the immediate proxy.
 */

/**
 * Bucket requests by the real client IP, IPv6-safe.
 *
 * `req.ip` is already populated correctly because `trust proxy` is
 * set to `1` in Spire's constructor. We still run it through
 * `ipKeyGenerator` so IPv4-mapped IPv6 (`::ffff:1.2.3.4`) doesn't
 * collide with unrelated IPv6 addresses in the same /56.
 */
const keyByIp = (req: Request): string => ipKeyGenerator(req.ip ?? "");

/**
 * Global per-IP limiter. Applied app-wide via `api.use(globalLimiter)`.
 *
 * 3000 requests per 15 minutes per client IP. A human chatting via a
 * browser or the libvex client won't come close; a single-host DoS
 * gets throttled quickly.
 */
export const globalLimiter = rateLimit({
    keyGenerator: keyByIp,
    legacyHeaders: false,
    limit: 3000,
    skip: devApiKeySkipsRateLimits,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Strict auth endpoint limiter. Applied per-route to /auth, /register,
 * and /auth/device.
 *
 * 50 failed attempts per 15 minutes per IP. Successful logins don't
 * count (`skipSuccessfulRequests`), so a normal user doesn't lock
 * themselves out by fat-fingering a password once. Blocks brute force
 * (CWE-307) without harming UX.
 */
export const authLimiter = rateLimit({
    keyGenerator: keyByIp,
    legacyHeaders: false,
    limit: 50,
    skip: devApiKeySkipsRateLimits,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    windowMs: 15 * 60 * 1000,
});

/**
 * Upload endpoint limiter. Applied per-route to /file and /avatar
 * POSTs, BEFORE multer parses the multipart body. Caps the number of
 * upload attempts per minute so an attacker can't force spire to
 * spend CPU/IO on repeated large-body parses.
 *
 * 200 uploads per minute per IP — generous for a chat client (rapid-
 * fire image attachments) but tight enough to shield the disk.
 */
export const uploadLimiter = rateLimit({
    keyGenerator: keyByIp,
    legacyHeaders: false,
    limit: 200,
    skip: devApiKeySkipsRateLimits,
    standardHeaders: "draft-7",
    windowMs: 60 * 1000,
});
