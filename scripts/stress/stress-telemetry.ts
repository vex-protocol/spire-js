/**
 * Live run telemetry for the stress web UI (facets, failures, SSE push).
 */
import type { StressLoadPacing } from "./stress-load-pacing.ts";

import { randomUUID } from "node:crypto";

import { isAxiosError } from "axios";

import {
    facetIdsForScenario,
    normalizeStressSurfaceKey,
    STRESS_FACET_CATALOG,
    type StressFacetCatalogEntry,
} from "./stress-api-catalog.ts";
import {
    failureCorrelationKey,
    groupStressFailures,
    type StressFailureGroupRow,
} from "./stress-correlation.ts";
import { settleOne, type HttpExpectStats } from "./stress-http-stats.ts";
import {
    facetToLibvexSurface,
    formatHarnessCallNotation,
    sanitizeRequestInputs,
} from "./stress-request-context.ts";

export interface TelemetryTouchCtx {
    readonly burst: number;
    readonly clientIndex?: number;
    readonly extra?: Readonly<Record<string, unknown>>;
    readonly opId?: string;
    readonly phase: string;
    /** Sanitized request params (passwords / tokens redacted). */
    readonly requestInputs?: Readonly<Record<string, unknown>>;
}

export interface StressFailureRecord {
    readonly at: number;
    readonly axios?: Readonly<{
        readonly dataSnippet: string | null;
        readonly message: string | null;
        readonly method: string | null;
        readonly status: number | null;
        readonly statusText: string | null;
        readonly url: string | null;
    }>;
    readonly burst: number;
    /** Stable key from libvex `protocolPath` + normalized message + top stack line. */
    readonly correlationKey: string;
    readonly clientIndex?: number;
    readonly surfaceKey: string;
    readonly surfaceTitle?: string;
    readonly extraContext?: Readonly<Record<string, unknown>>;
    readonly id: string;
    /** Primary libvex / API surface label (from facet catalog). */
    readonly libvexSurface: string;
    /** Published Client API path(s) from catalog, e.g. `Client.invites.retrieve`. */
    readonly protocolPath: string;
    readonly message: string;
    readonly opId?: string;
    readonly phase: string;
    readonly requestInputs?: Readonly<Record<string, unknown>>;
    readonly stack?: string;
}

export interface StressRequestLogEntry {
    readonly at: number;
    readonly surfaceKey: string;
    readonly inputs?: Readonly<Record<string, unknown>>;
    readonly libvexSurface: string;
    readonly ok: true;
}

/** Deduped error types on one Client surface (grouped by {@link StressFailureRecord.surfaceKey}). */
export interface StressFacetErrorGroupRow {
    readonly correlationKey: string;
    readonly count: number;
    readonly lastAt: number;
    readonly libvexSurface: string;
    readonly protocolPath: string;
    readonly sampleMessage: string;
    readonly sampleRequestInputs?: Readonly<Record<string, unknown>>;
}

function runPhasePublicLabel(phase: string): string {
    switch (phase) {
        case "init":
            return "Initializing";
        case "bootstrap":
            return "Account and session setup";
        case "flood":
            return "Flood phase (synchronized walls)";
        case "done":
            return "Run finished";
        default:
            return phase;
    }
}

function computeErrorsByFacet(
    failures: readonly StressFailureRecord[],
): Record<string, StressFacetErrorGroupRow[]> {
    const byFacet = new Map<string, Map<string, StressFacetErrorGroupRow>>();
    for (const f of failures) {
        let inner = byFacet.get(f.surfaceKey);
        if (inner === undefined) {
            inner = new Map();
            byFacet.set(f.surfaceKey, inner);
        }
        const row = inner.get(f.correlationKey);
        if (row === undefined) {
            inner.set(f.correlationKey, {
                correlationKey: f.correlationKey,
                count: 1,
                lastAt: f.at,
                libvexSurface: f.libvexSurface,
                protocolPath: f.protocolPath,
                sampleMessage: f.message,
                sampleRequestInputs: f.requestInputs,
            });
        } else {
            inner.set(f.correlationKey, {
                ...row,
                count: row.count + 1,
                lastAt: f.at > row.lastAt ? f.at : row.lastAt,
            });
        }
    }
    const out: Record<string, StressFacetErrorGroupRow[]> = {};
    for (const [surfaceKey, inner] of byFacet) {
        const rows = [...inner.values()].sort((a, b) => b.count - a.count);
        out[surfaceKey] = rows;
    }
    return out;
}

function catalogOrSynthetic(surfaceKey: string): StressFacetCatalogEntry {
    const key = normalizeStressSurfaceKey(surfaceKey);
    const known = STRESS_FACET_CATALOG[key];
    if (known !== undefined) {
        return known;
    }
    return {
        apiCall: surfaceKey,
        description: "Surface not listed in catalog.",
        group: "load",
        protocolPath: `Unknown (${surfaceKey})`,
        title: surfaceKey,
    };
}

/** Cap stored stacks so the failure ring cannot retain MB of V8 stack text each. */
const MAX_STORED_STACK_CHARS = 16_000;

function clipStoredStack(stack: string | undefined): string | undefined {
    if (stack === undefined || stack.length === 0) {
        return undefined;
    }
    if (stack.length <= MAX_STORED_STACK_CHARS) {
        return stack;
    }
    return `${stack.slice(0, MAX_STORED_STACK_CHARS)}\n… [truncated ${String(stack.length - MAX_STORED_STACK_CHARS)} chars]`;
}

function serializeAxios(
    err: unknown,
): StressFailureRecord["axios"] | undefined {
    if (!isAxiosError(err)) {
        return undefined;
    }
    const st = err.response?.status;
    const data: unknown = err.response?.data;
    let dataSnippet: string | null = null;
    if (data !== undefined) {
        try {
            const s = typeof data === "string" ? data : JSON.stringify(data);
            dataSnippet = s.length > 2000 ? `${s.slice(0, 2000)}…` : s;
        } catch {
            dataSnippet = "[unserializable body]";
        }
    }
    return {
        dataSnippet,
        message: err.message,
        method: err.config?.method?.toUpperCase() ?? null,
        status: typeof st === "number" ? st : null,
        statusText: err.response?.statusText ?? null,
        url:
            typeof err.config?.url === "string"
                ? err.config.url
                : (err.config?.baseURL ?? null),
    };
}

const MAX_REQUEST_RING = 80;

export class StressTelemetry {
    private readonly scenario: string;
    private readonly facets = new Map<
        string,
        {
            readonly def: StressFacetCatalogEntry;
            fail: number;
            ok: number;
        }
    >();
    private readonly failures: StressFailureRecord[] = [];
    private readonly recentRequests: StressRequestLogEntry[] = [];
    private readonly listeners = new Set<(snap: StressUiSnapshot) => void>();
    private dirty = true;
    private pushTimer: ReturnType<typeof setTimeout> | null = null;
    private host = "";
    private clientCount = 0;
    private concurrency = 0;
    private currentBurst = 0;
    private phase = "init";
    private completedOps = 0;
    private lastBurstMs: number | null = null;
    /** Last completed flood burst: `ops × 1000 / wall_ms` from the harness (logical slots, not HTTP count). */
    private lastBurstOfferedSlotsPerSec: number | null = null;
    private runStartedAt = Date.now();
    private forever = true;
    private plannedRounds = 0;
    private loadPacing: StressLoadPacing = "immediate";
    private burstGapMs = 0;
    /** Recent `touchOk` / `touchFail` timestamps for live ops/s (1s window). */
    private readonly opTouchAt: number[] = [];
    /** Web UI queued a restart (cleared when the harness begins applying it). */
    private restartPending = false;

    public constructor(scenario: string) {
        this.scenario = scenario;
        for (const id of facetIdsForScenario(scenario)) {
            this.facets.set(id, {
                def: catalogOrSynthetic(id),
                fail: 0,
                ok: 0,
            });
        }
    }

    public setRunBanner(opts: {
        readonly burstGapMs?: number;
        readonly clientCount: number;
        readonly concurrency: number;
        readonly forever: boolean;
        readonly host: string;
        readonly loadPacing?: StressLoadPacing;
        readonly plannedRounds: number;
    }): void {
        this.host = opts.host;
        this.clientCount = opts.clientCount;
        this.concurrency = opts.concurrency;
        this.forever = opts.forever;
        this.plannedRounds = opts.plannedRounds;
        this.loadPacing = opts.loadPacing ?? "immediate";
        this.burstGapMs =
            typeof opts.burstGapMs === "number" && opts.burstGapMs >= 0
                ? opts.burstGapMs
                : 0;
        this.markDirty();
    }

    /** Full reset between harness sessions (same SSE subscribers). */
    public resetSessionForNewRun(opts: {
        readonly burstGapMs?: number;
        readonly clientCount: number;
        readonly concurrency: number;
        readonly forever: boolean;
        readonly host: string;
        readonly loadPacing?: StressLoadPacing;
        readonly plannedRounds: number;
    }): void {
        this.failures.length = 0;
        this.recentRequests.length = 0;
        this.opTouchAt.length = 0;
        for (const row of this.facets.values()) {
            row.ok = 0;
            row.fail = 0;
        }
        this.completedOps = 0;
        this.currentBurst = 0;
        this.lastBurstMs = null;
        this.lastBurstOfferedSlotsPerSec = null;
        this.phase = "init";
        this.runStartedAt = Date.now();
        this.setRunBanner(opts);
        this.markDirty(true);
    }

    public setRestartPending(pending: boolean): void {
        this.restartPending = pending;
        this.markDirty();
    }

    public setPhase(phase: string): void {
        this.phase = phase;
        this.markDirty();
    }

    public setBurstContext(burst: number, concurrency: number): void {
        this.currentBurst = burst;
        this.concurrency = concurrency;
        this.markDirty();
    }

    public setConcurrency(concurrency: number): void {
        this.concurrency = concurrency;
        this.markDirty();
    }

    public setProgress(
        completedOps: number,
        lastBurstMs: number | null,
        lastBurstOfferedSlotsPerSec: number | null = null,
    ): void {
        this.completedOps = completedOps;
        this.lastBurstMs = lastBurstMs;
        this.lastBurstOfferedSlotsPerSec = lastBurstOfferedSlotsPerSec;
        this.markDirty();
    }

    /** Successful operation for this libvex surface (`Client.*` catalog key). */
    public touchOk(surfaceKey: string, ctx?: TelemetryTouchCtx): void {
        const key = normalizeStressSurfaceKey(surfaceKey);
        const row = this.ensureFacet(key);
        row.ok += 1;
        if (
            process.env.SPIRE_STRESS_LOG_REQUESTS === "1" &&
            ctx?.requestInputs !== undefined
        ) {
            this.pushRecentRequest({
                at: Date.now(),
                inputs: sanitizeRequestInputs(
                    ctx.requestInputs as Record<string, unknown>,
                ),
                libvexSurface: facetToLibvexSurface(key),
                ok: true,
                surfaceKey: key,
            });
        }
        this.recordOpTouch();
        this.markDirty();
    }

    private recordOpTouch(): void {
        const t = Date.now();
        this.opTouchAt.push(t);
        const cutoff = t - 2000;
        while (this.opTouchAt.length > 0) {
            const first = this.opTouchAt[0];
            if (first === undefined || first >= cutoff) {
                break;
            }
            this.opTouchAt.shift();
        }
        if (this.opTouchAt.length > 5000) {
            this.opTouchAt.splice(0, this.opTouchAt.length - 5000);
        }
    }

    private pushRecentRequest(entry: StressRequestLogEntry): void {
        this.recentRequests.unshift(entry);
        if (this.recentRequests.length > MAX_REQUEST_RING) {
            this.recentRequests.length = MAX_REQUEST_RING;
        }
    }

    /** Failed operation; records failure log entry. */
    public touchFail(
        surfaceKey: string,
        ctx: TelemetryTouchCtx,
        err: unknown,
    ): void {
        const key = normalizeStressSurfaceKey(surfaceKey);
        const row = this.ensureFacet(key);
        row.fail += 1;
        const message =
            err instanceof Error
                ? err.message
                : typeof err === "string"
                  ? err
                  : "Unknown error";
        const rawStack = err instanceof Error ? err.stack : undefined;
        const def = catalogOrSynthetic(key);
        const libvexSurface = facetToLibvexSurface(key);
        const protocolPath = def.protocolPath;
        const correlationKey = failureCorrelationKey({
            message,
            protocolPath,
            stack: rawStack,
        });
        const requestInputs =
            ctx.requestInputs !== undefined
                ? sanitizeRequestInputs(
                      ctx.requestInputs as Record<string, unknown>,
                  )
                : undefined;
        const extraContext =
            ctx.extra !== undefined
                ? sanitizeRequestInputs(ctx.extra as Record<string, unknown>)
                : undefined;
        const rec: StressFailureRecord = {
            at: Date.now(),
            axios: serializeAxios(err),
            burst: ctx.burst,
            clientIndex: ctx.clientIndex,
            correlationKey,
            extraContext,
            id: randomUUID(),
            libvexSurface,
            message,
            opId: ctx.opId,
            phase: ctx.phase,
            protocolPath,
            requestInputs,
            stack: clipStoredStack(rawStack),
            surfaceKey: key,
            surfaceTitle: def.title,
        };
        this.failures.unshift(rec);
        if (this.failures.length > 250) {
            this.failures.length = 250;
        }
        this.recordOpTouch();
        this.markDirty(true);
    }

    private serializeFailureSample(
        f: StressFailureRecord,
    ): Record<string, unknown> {
        const stack =
            f.stack !== undefined
                ? f.stack.split("\n").slice(0, 48).join("\n")
                : undefined;
        return {
            at: f.at,
            axios: f.axios,
            burst: f.burst,
            clientIndex: f.clientIndex,
            clientSurfaceKey: f.surfaceKey,
            extra: f.extraContext,
            harnessCall: formatHarnessCallNotation(
                f.protocolPath,
                f.requestInputs,
            ),
            message: f.message,
            primaryClientPath: facetToLibvexSurface(f.surfaceKey),
            protocolPath: f.protocolPath,
            requestInputs: f.requestInputs,
            runPhase: f.phase,
            runPhaseLabel: runPhasePublicLabel(f.phase),
            stack,
            surfaceTitle: f.surfaceTitle,
        };
    }

    /** Rolling count of client op completions (ok + fail) in the last ~1s. */
    private computeOpsPerSecond(): number {
        const t = Date.now();
        const windowMs = 1000;
        const cutoff = t - windowMs;
        let n = 0;
        for (let i = this.opTouchAt.length - 1; i >= 0; i--) {
            const touch = this.opTouchAt[i];
            if (touch === undefined || touch < cutoff) {
                break;
            }
            n++;
        }
        return n;
    }

    public subscribe(fn: (snap: StressUiSnapshot) => void): () => void {
        this.listeners.add(fn);
        fn(this.getSnapshot());
        return () => {
            this.listeners.delete(fn);
        };
    }

    public getSnapshot(): StressUiSnapshot {
        const facetRows: StressUiFacetRow[] = [];
        for (const id of facetIdsForScenario(this.scenario)) {
            const row = this.facets.get(id);
            if (row === undefined) {
                continue;
            }
            const total = row.ok + row.fail;
            let status: "idle" | "ok" | "warn" | "fail";
            if (total === 0) {
                status = "idle";
            } else if (row.fail === 0) {
                status = "ok";
            } else if (row.ok === 0) {
                status = "fail";
            } else {
                status = "warn";
            }
            facetRows.push({
                apiCall: row.def.apiCall,
                description: row.def.description,
                fail: row.fail,
                group: row.def.group,
                id,
                ok: row.ok,
                protocolPath: row.def.protocolPath,
                status,
                title: row.def.title,
            });
        }
        const failures = [...this.failures];
        const failureGroups = groupStressFailures(
            failures.map((f) => ({
                correlationKey: f.correlationKey,
                id: f.id,
                libvexSurface: f.libvexSurface,
                message: f.message,
                protocolPath: f.protocolPath,
                surfaceKey: f.surfaceKey,
            })),
        );
        const errorsByFacet =
            failures.length > 0 ? computeErrorsByFacet(failures) : undefined;
        return {
            burstGapMs: this.burstGapMs,
            clientCount: this.clientCount,
            completedOps: this.completedOps,
            concurrency: this.concurrency,
            currentBurst: this.currentBurst,
            errorsByFacet,
            failureGroups,
            failures,
            facets: facetRows,
            forever: this.forever,
            host: this.host,
            lastBurstMs: this.lastBurstMs,
            lastBurstOfferedSlotsPerSec: this.lastBurstOfferedSlotsPerSec,
            loadPacing: this.loadPacing,
            phase: this.phase,
            plannedRounds: this.plannedRounds,
            opsPerSecond1s: this.computeOpsPerSecond(),
            restartPending: this.restartPending,
            recentRequests:
                this.recentRequests.length > 0
                    ? [...this.recentRequests]
                    : undefined,
            runStartedAt: this.runStartedAt,
            scenario: this.scenario,
        };
    }

    private ensureFacet(id: string): {
        def: StressFacetCatalogEntry;
        fail: number;
        ok: number;
    } {
        let row = this.facets.get(id);
        if (row === undefined) {
            row = { def: catalogOrSynthetic(id), fail: 0, ok: 0 };
            this.facets.set(id, row);
        }
        return row;
    }

    private markDirty(immediate = false): void {
        this.dirty = true;
        if (immediate) {
            this.flush();
            return;
        }
        if (this.pushTimer !== null) {
            return;
        }
        this.pushTimer = setTimeout(() => {
            this.pushTimer = null;
            this.flush();
        }, 120);
    }

    private flush(): void {
        if (!this.dirty) {
            return;
        }
        this.dirty = false;
        const snap = this.getSnapshot();
        for (const fn of this.listeners) {
            fn(snap);
        }
    }
}

export interface StressUiFacetRow {
    readonly apiCall: string;
    readonly description: string;
    readonly fail: number;
    readonly group: StressFacetCatalogEntry["group"];
    readonly id: string;
    readonly ok: number;
    readonly protocolPath: string;
    readonly status: "idle" | "ok" | "warn" | "fail";
    readonly title: string;
}

/** Count HTTP outcome and record facet ok/fail for the stress web UI. */
export async function settleWithTelemetry<T>(
    stats: HttpExpectStats,
    telemetry: StressTelemetry | null,
    surfaceKey: string,
    ctx: TelemetryTouchCtx,
    p: Promise<T>,
    requestMeta?: {
        readonly inputs?: Readonly<Record<string, unknown>>;
    },
): Promise<T> {
    const mergedCtx: TelemetryTouchCtx =
        requestMeta?.inputs !== undefined
            ? { ...ctx, requestInputs: requestMeta.inputs }
            : ctx;
    try {
        const v = await settleOne(stats, p);
        telemetry?.touchOk(surfaceKey, mergedCtx);
        return v;
    } catch (err: unknown) {
        telemetry?.touchFail(surfaceKey, mergedCtx, err);
        throw err;
    }
}

export interface StressUiSnapshot {
    readonly burstGapMs: number;
    readonly clientCount: number;
    readonly completedOps: number;
    readonly concurrency: number;
    readonly currentBurst: number;
    readonly errorsByFacet?: Readonly<
        Record<string, readonly StressFacetErrorGroupRow[]>
    >;
    readonly failureGroups: readonly StressFailureGroupRow[];
    readonly failures: readonly StressFailureRecord[];
    readonly facets: readonly StressUiFacetRow[];
    readonly forever: boolean;
    readonly host: string;
    readonly lastBurstMs: number | null;
    /** `ops×1000/wall_ms` for the last finished burst (logical slot completions; not raw HTTP RPS). */
    readonly lastBurstOfferedSlotsPerSec: number | null;
    readonly loadPacing: StressLoadPacing;
    readonly phase: string;
    readonly plannedRounds: number;
    /** Client op completions (telemetry touches) in the last ~1 second. */
    readonly opsPerSecond1s: number;
    readonly restartPending: boolean;
    readonly recentRequests?: readonly StressRequestLogEntry[];
    readonly runStartedAt: number;
    readonly scenario: string;
}
