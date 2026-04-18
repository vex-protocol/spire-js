/**
 * Count libvex HTTP outcomes (success vs Axios status vs other errors).
 */
import { isAxiosError } from "axios";

export interface HttpExpectStats {
    /** Successful round-trips we explicitly counted (2xx implied). */
    ok: number;
    /** Non-2xx or Axios errors with a response status. */
    byStatus: Record<number, number>;
    /** Rejects without an HTTP status (WS, login message-only failures, etc.). */
    other: number;
}

export function createHttpExpectStats(): HttpExpectStats {
    return { byStatus: {}, ok: 0, other: 0 };
}

export function recordHttpFailure(stats: HttpExpectStats, err: unknown): void {
    if (isAxiosError(err) && typeof err.response?.status === "number") {
        const c = err.response.status;
        stats.byStatus[c] = (stats.byStatus[c] ?? 0) + 1;
    } else {
        stats.other += 1;
    }
}

export function httpFailureTotal(stats: HttpExpectStats): number {
    let n = stats.other;
    for (const v of Object.values(stats.byStatus)) {
        n += v;
    }
    return n;
}

export type TrackSoftResult =
    | { readonly ok: true }
    | { readonly ok: false; readonly cause?: unknown };

/** Like {@link settleOne} but never throws; returns success vs optional rejection cause. */
export async function trackSoftResult(
    stats: HttpExpectStats,
    p: Promise<unknown>,
): Promise<TrackSoftResult> {
    try {
        await p;
        stats.ok += 1;
        return { ok: true };
    } catch (err: unknown) {
        recordHttpFailure(stats, err);
        return { ok: false, cause: err };
    }
}

/** Like {@link settleOne} but never throws; returns whether the promise settled successfully. */
export async function trackSoft(
    stats: HttpExpectStats,
    p: Promise<unknown>,
): Promise<boolean> {
    const r = await trackSoftResult(stats, p);
    return r.ok;
}

export async function settleOne<T>(
    stats: HttpExpectStats,
    p: Promise<T>,
): Promise<T> {
    try {
        const v = await p;
        stats.ok += 1;
        return v;
    } catch (err: unknown) {
        recordHttpFailure(stats, err);
        throw err;
    }
}

/** Run promises in parallel; count every outcome; throw the first rejection if any failed. */
export async function allTracked(
    stats: HttpExpectStats,
    promises: readonly Promise<unknown>[],
): Promise<void> {
    const results = await Promise.allSettled(promises);
    for (const r of results) {
        if (r.status === "fulfilled") {
            stats.ok += 1;
        } else {
            recordHttpFailure(stats, r.reason);
        }
    }
    let firstReject: unknown;
    for (const r of results) {
        if (r.status === "rejected") {
            firstReject = r.reason;
            break;
        }
    }
    if (firstReject !== undefined) {
        if (firstReject instanceof Error) {
            throw firstReject;
        }
        const msg =
            typeof firstReject === "string"
                ? firstReject
                : "One or more tracked requests failed.";
        throw new Error(msg);
    }
}

export function formatHttpExpectLine(
    stats: HttpExpectStats,
    width: number,
): string {
    const parts: string[] = [`ok ${String(stats.ok)}`];
    const codes = Object.keys(stats.byStatus)
        .map((k) => Number(k))
        .filter((n) => Number.isFinite(n))
        .sort((a, b) => a - b);
    for (const c of codes) {
        const n = stats.byStatus[c];
        if (n !== undefined && n > 0) {
            parts.push(`${String(c)}×${String(n)}`);
        }
    }
    if (stats.other > 0) {
        parts.push(`other×${String(stats.other)}`);
    }
    let s = parts.join("  ");
    if (s.length > width) {
        s = `${s.slice(0, Math.max(0, width - 1))}…`;
    }
    return s;
}
