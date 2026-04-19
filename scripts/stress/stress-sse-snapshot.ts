/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Smaller snapshots for SSE / JSON responses so Node does not build multi‑MB
 * `JSON.stringify` strings on every telemetry flush (heap OOM under load).
 */
import type {
    StressFailureRecord,
    StressRequestLogEntry,
    StressUiSnapshot,
} from "./stress-telemetry.ts";

const MAX_WIRE_FAILURES = 120;
const MAX_WIRE_STACK = 10_000;
const MAX_WIRE_MESSAGE = 4000;
const MAX_WIRE_AXIOS_SNIPPET = 1200;
const MAX_WIRE_RECENT_REQUESTS = 40;

function clipStrNum(s: string, maxLen: number): string {
    if (s.length <= maxLen) {
        return s;
    }
    return `${s.slice(0, maxLen)}…`;
}

function slimAxios(
    ax: StressFailureRecord["axios"],
): StressFailureRecord["axios"] | undefined {
    if (ax === undefined) {
        return undefined;
    }
    const dataSnippet =
        typeof ax.dataSnippet === "string" &&
        ax.dataSnippet.length > MAX_WIRE_AXIOS_SNIPPET
            ? `${ax.dataSnippet.slice(0, MAX_WIRE_AXIOS_SNIPPET)}…`
            : ax.dataSnippet;
    return { ...ax, dataSnippet };
}

function slimFailure(f: StressFailureRecord): StressFailureRecord {
    const stack =
        typeof f.stack === "string" && f.stack.length > MAX_WIRE_STACK
            ? `${f.stack.slice(0, MAX_WIRE_STACK)}\n… [stack truncated for wire]`
            : f.stack;
    const message = clipStrNum(f.message, MAX_WIRE_MESSAGE);
    return {
        ...f,
        axios: slimAxios(f.axios),
        message,
        stack,
    };
}

function slimRecent(r: StressRequestLogEntry): StressRequestLogEntry {
    if (r.inputs === undefined) {
        return r;
    }
    try {
        const j = JSON.stringify(r.inputs);
        if (j.length <= 2400) {
            return r;
        }
        return {
            ...r,
            inputs: { _truncated: `${j.slice(0, 2400)}…` },
        };
    } catch {
        return { ...r, inputs: { _truncated: "[unserializable]" } };
    }
}

/** Snapshot safe for frequent `JSON.stringify` (SSE + optional /api/snapshot). */
export function slimStressUiSnapshotForWire(
    snap: StressUiSnapshot,
): StressUiSnapshot {
    const failures = snap.failures.slice(0, MAX_WIRE_FAILURES).map(slimFailure);
    const recent =
        snap.recentRequests !== undefined
            ? snap.recentRequests
                  .slice(0, MAX_WIRE_RECENT_REQUESTS)
                  .map(slimRecent)
            : undefined;
    return {
        ...snap,
        failures,
        recentRequests: recent,
    };
}
