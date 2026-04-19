/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Idle policy between completed flood walls. Each wall is still one synchronized
 * all slots completing each wall — this only controls whether the harness sleeps
 * before starting the next wall.
 *
 * Canonical: `immediate` | `paced`. Legacy env values `continuous` and `burst` are
 * still accepted (see {@link parseStressLoadPacing}).
 */
export type StressLoadPacing = "immediate" | "paced";

/**
 * Parse `SPIRE_STRESS_LOAD_MODE`, web restart `loadPacing` / legacy `loadMode`, or CLI `--load`.
 *
 * - **paced** — `paced`, `burst` (legacy): optional idle gap between walls (`SPIRE_STRESS_BURST_GAP_MS`).
 * - **immediate** — `immediate`, `continuous` (legacy), empty, or unknown: start the next wall as soon as the previous finishes.
 */
export function parseStressLoadPacing(
    raw: string | undefined,
): StressLoadPacing {
    const t = (raw ?? "").trim().toLowerCase();
    if (t === "burst" || t === "paced") {
        return "paced";
    }
    return "immediate";
}
