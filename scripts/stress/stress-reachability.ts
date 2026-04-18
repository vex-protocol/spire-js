/**
 * Classify errors where Spire is probably not running or not reachable on HTTP.
 * Used only to improve stress harness UX — no root-cause guessing beyond transport.
 */
import { isAxiosError } from "axios";

const UNREACHABLE_BANNER = "── Spire stress: target server unreachable ──";

export function isLikelySpireDown(err: unknown): boolean {
    if (isAxiosError(err) && err.response === undefined) {
        return true;
    }
    if (!(err instanceof Error)) {
        return false;
    }
    const m = err.message;
    const needles = [
        "Couldn't get regkey from server",
        "ECONNREFUSED",
        "ENOTFOUND",
        "ETIMEDOUT",
        "EAI_AGAIN",
        "ECONNRESET",
        "socket hang up",
        "Network Error",
    ];
    return needles.some((n) => m.includes(n));
}

/** Wrap for a single clear stderr block (detected in main catch). */
export function wrapSpireUnreachable(host: string, err: unknown): Error {
    const base = err instanceof Error ? err.message : String(err);
    return new Error(
        [
            UNREACHABLE_BANNER,
            `  Target (SPIRE_STRESS_HOST): ${host}`,
            "  No HTTP response from Spire for a required step (wrong host/port, or server not started).",
            "  Start Spire first (e.g. npm start in this repo), then re-run the stress harness.",
            `  Underlying error: ${base}`,
        ].join("\n"),
    );
}

export function isWrappedSpireUnreachable(err: unknown): boolean {
    return err instanceof Error && err.message.includes(UNREACHABLE_BANNER);
}
