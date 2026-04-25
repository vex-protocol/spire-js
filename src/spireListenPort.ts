/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Default HTTP/WS port for the Spire API (tweetnacl and FIPS), unless
 * `API_PORT` / `apiPort` is set. Clients can tell profiles apart via `GET /status`.
 */
export const DEFAULT_SPIRE_API_PORT = 16777;

/**
 * @param explicit - `apiPort` from `SpireOptions` or `API_PORT` when set.
 */
export function resolveSpireListenPort(explicit: number | undefined): number {
    if (
        typeof explicit === "number" &&
        Number.isFinite(explicit) &&
        explicit > 0
    ) {
        return Math.trunc(explicit);
    }
    return DEFAULT_SPIRE_API_PORT;
}
