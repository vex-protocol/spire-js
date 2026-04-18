/**
 * Structured JSON written on fatal harness errors for GitHub issues / LLM triage.
 * Contains only observed data (run snapshot, error, telemetry slice, correlation).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import {
    normalizeStressSurfaceKey,
    protocolPathForStressFacet,
} from "./stress-api-catalog.ts";
import { groupStressFailures } from "./stress-correlation.ts";
import { facetToLibvexSurface } from "./stress-request-context.ts";

export const STRESS_ISSUE_BUNDLE_PATH = join(
    homedir(),
    ".spire-stress",
    "last-issue-bundle.json",
);

export interface StressIssueBundleV1 {
    readonly correlation: {
        readonly failureGroups: ReturnType<typeof groupStressFailures>;
    };
    readonly fatal: {
        readonly kind: "uncaughtException" | "unhandledRejection";
        readonly message: string;
        readonly stack: string | null;
    };
    readonly generatedAt: string;
    readonly run: Record<string, unknown>;
    readonly schema: "spire-stress-issue-bundle@1";
    readonly telemetry: unknown;
}

function safeJson(value: unknown): unknown {
    try {
        return JSON.parse(JSON.stringify(value)) as unknown;
    } catch {
        return { _error: "telemetry_snapshot_not_json_serializable" };
    }
}

function readStr(obj: unknown, key: string): string {
    if (typeof obj !== "object" || obj === null) {
        return "";
    }
    const v: unknown = Reflect.get(obj, key);
    return typeof v === "string" ? v : "";
}

export function buildFatalIssueBundle(input: {
    readonly run: Record<string, unknown>;
    readonly kind: "uncaughtException" | "unhandledRejection";
    readonly reason: unknown;
    readonly telemetrySnapshot: unknown;
}): StressIssueBundleV1 {
    const err = input.reason;
    const message =
        err instanceof Error
            ? err.message
            : typeof err === "string"
              ? err
              : String(err);
    const stack = err instanceof Error ? (err.stack ?? null) : null;

    let failureGroups: ReturnType<typeof groupStressFailures> = [];
    const snap = input.telemetrySnapshot;
    const failuresField =
        typeof snap === "object" && snap !== null && "failures" in snap
            ? Reflect.get(snap, "failures")
            : undefined;
    if (Array.isArray(failuresField)) {
        const rows: {
            correlationKey: string;
            id: string;
            libvexSurface?: string;
            message: string;
            protocolPath?: string;
            surfaceKey: string;
        }[] = [];
        for (const item of failuresField as readonly unknown[]) {
            const correlationKey = readStr(item, "correlationKey");
            const rawKey =
                readStr(item, "surfaceKey").length > 0
                    ? readStr(item, "surfaceKey")
                    : readStr(item, "facetId");
            const surfaceKey = normalizeStressSurfaceKey(rawKey);
            const id = readStr(item, "id");
            const msg = readStr(item, "message");
            const storedSurface = readStr(item, "libvexSurface");
            const libvexSurface =
                storedSurface.length > 0
                    ? storedSurface
                    : facetToLibvexSurface(surfaceKey);
            const storedPath = readStr(item, "protocolPath");
            const protocolPath =
                storedPath.length > 0
                    ? storedPath
                    : protocolPathForStressFacet(surfaceKey);
            if (
                correlationKey.length > 0 &&
                surfaceKey.length > 0 &&
                id.length > 0
            ) {
                rows.push({
                    correlationKey,
                    id,
                    libvexSurface,
                    message: msg,
                    protocolPath,
                    surfaceKey,
                });
            }
        }
        failureGroups = groupStressFailures(rows);
    }

    return {
        correlation: { failureGroups },
        fatal: {
            kind: input.kind,
            message,
            stack,
        },
        generatedAt: new Date().toISOString(),
        run: input.run,
        schema: "spire-stress-issue-bundle@1",
        telemetry: safeJson(input.telemetrySnapshot),
    };
}

export function writeFatalIssueBundle(bundle: StressIssueBundleV1): string {
    mkdirSync(dirname(STRESS_ISSUE_BUNDLE_PATH), { recursive: true });
    writeFileSync(
        STRESS_ISSUE_BUNDLE_PATH,
        `${JSON.stringify(bundle, null, 2)}\n`,
        "utf8",
    );
    return STRESS_ISSUE_BUNDLE_PATH;
}
