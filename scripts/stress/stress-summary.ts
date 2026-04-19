/**
 * Human-readable final report for the Spire stress harness.
 * Set SPIRE_STRESS_JSON=1 to also print a machine-readable JSON block.
 * Per-surface facet tallies (same as web UI): SPIRE_STRESS_FACET_REPORT=1 or default on in quiet/CI (WEB=0).
 */
import type { StressUiFacetRow, StressUiSnapshot } from "./stress-telemetry.ts";

export interface StressRunSummary {
    readonly burstCount: number;
    readonly clientCount: number;
    readonly concurrencySnapshot: number;
    readonly host: string;
    readonly httpRequestsCompleted: number;
    readonly httpResponsesByStatus: Readonly<Record<number, number>>;
    readonly httpResponsesOk: number;
    readonly httpResponsesOther: number;
    readonly lastConcurrency: number;
    readonly roundMedianMs: number;
    readonly roundP95Ms: number;
    readonly scenario: string;
    readonly shutDownReason: "completed" | "interrupt";
    readonly totalWallMs: number;
}

function scenarioPlainEnglish(scenario: string): string {
    switch (scenario) {
        case "whoami":
            return "whoami (light auth check)";
        case "servers":
            return "list servers (repeated)";
        case "chat":
            return "chat-shaped load (WS + one shared server, group + DM + history reads)";
        case "noise":
            return "RNG libvex noise (multi-user server, invites, DMs, group chat, files, emoji, …)";
        case "mixed":
        default:
            return "mixed reads (servers + permissions, 50/50 per wall)";
    }
}

const FACET_GROUP_LABEL: Record<"bootstrap" | "load" | "world", string> = {
    bootstrap: "Bootstrap",
    load: "Load — API under test",
    world: "Shared world",
};

/** Written by spire-stress when `SPIRE_STRESS_FACET_DUMP_PATH` is set (e.g. stress:cli matrix). */
export interface StressFacetDumpV1 {
    readonly facets: readonly StressUiFacetRow[];
    readonly host: string;
    readonly scenario: string;
    readonly v: 1;
}

function facetStatusFromCounts(
    ok: number,
    fail: number,
): StressUiFacetRow["status"] {
    const t = ok + fail;
    if (t === 0) {
        return "idle";
    }
    if (fail === 0) {
        return "ok";
    }
    if (ok === 0) {
        return "fail";
    }
    return "warn";
}

/**
 * Merge facet rows from multiple stress runs (same scenario catalog) by surface `id`.
 */
export function mergeStressFacetRowLists(
    lists: readonly (readonly StressUiFacetRow[])[],
): StressUiFacetRow[] {
    const byId = new Map<string, StressUiFacetRow>();
    for (const list of lists) {
        for (const f of list) {
            const p = byId.get(f.id);
            if (p === undefined) {
                byId.set(f.id, { ...f });
            } else {
                const ok = p.ok + f.ok;
                const fail = p.fail + f.fail;
                byId.set(f.id, {
                    ...p,
                    fail,
                    ok,
                    status: facetStatusFromCounts(ok, fail),
                });
            }
        }
    }
    return [...byId.values()].sort(
        (a, b) => a.group.localeCompare(b.group) || a.id.localeCompare(b.id),
    );
}

function padPathCell(s: string, width: number): string {
    const t = s.length > width ? `${s.slice(0, width - 1)}…` : s;
    return t + " ".repeat(Math.max(0, width - t.length));
}

/** Short label for tables — catalog `id` is usually tighter than full protocol prose. */
function condensedFacetRoute(f: StressUiFacetRow): string {
    const id = f.id.trim();
    if (id.length > 0 && id.length <= 44) {
        return id;
    }
    const p = f.protocolPath.trim();
    return p.length <= 44 ? p : `${p.slice(0, 41)}…`;
}

function facetGaugeEmoji(status: StressUiFacetRow["status"]): string {
    switch (status) {
        case "ok":
            return "✅";
        case "warn":
            return "⚠️";
        case "fail":
            return "⛔";
        default:
            return "⬚";
    }
}

export interface StressFacetReportFormatInput {
    readonly facets: readonly StressUiFacetRow[];
    readonly host: string;
    readonly scenario: string;
}

/**
 * Per-libvex-surface table (telemetry touches), grouped like the web dashboard.
 * Only surfaces with at least one completion (ok+fail &gt; 0) are listed unless `includeIdle` is true.
 */
export function formatStressFacetCiReport(
    snap: StressUiSnapshot | StressFacetReportFormatInput,
    options?: { readonly headline?: string; readonly includeIdle?: boolean },
): string {
    const includeIdle = options?.includeIdle === true;
    const rawFacets = snap.facets;
    const rows = includeIdle
        ? [...rawFacets]
        : rawFacets.filter((f) => f.ok + f.fail > 0);
    const headline =
        options?.headline ??
        `scenario=${snap.scenario}  ·  target=${snap.host}`;
    const routeW = 44;
    const lines: string[] = [
        "",
        "═══════════════════════════════════════════════════════════════════",
        `  Spire stress · API facets`,
        `  ${headline}`,
        "═══════════════════════════════════════════════════════════════════",
        "",
    ];
    const groups = ["bootstrap", "world", "load"] as const;
    let any = false;
    for (const g of groups) {
        const inGroup = rows.filter((f) => f.group === g);
        if (inGroup.length === 0) {
            continue;
        }
        any = true;
        lines.push(` ▸ ${FACET_GROUP_LABEL[g]}`);
        lines.push(
            `   ${padPathCell("surface (catalog id)", routeW)}     ✓ ok      ✗ fail     Σ   `,
        );
        lines.push(`   ${"─".repeat(72)}`);
        for (const f of inGroup) {
            const total = f.ok + f.fail;
            const route = condensedFacetRoute(f);
            const gEmoji = facetGaugeEmoji(f.status);
            lines.push(
                `   ${padPathCell(route, routeW)}  ✓ ${String(f.ok).padStart(6)}   ✗ ${String(f.fail).padStart(6)}   ${String(total).padStart(5)}  ${gEmoji}`,
            );
        }
        lines.push("");
    }
    if (!any) {
        lines.push("   (no facet touches — check harness / telemetry wiring.)");
        lines.push("");
    }
    return lines.join("\n");
}

/** Short stdout block for headless / CI (`SPIRE_STRESS_WEB=0`, no tutorial copy). */
export function formatStressRunSummaryQuiet(s: StressRunSummary): string {
    const lines = [
        "",
        `stress · ${s.host} · ${s.scenario} · ${String(s.burstCount)} walls · clients ${String(s.clientCount)} · conc ${String(s.lastConcurrency)}`,
        `  HTTP ok ${String(s.httpResponsesOk)} · non-2xx/other ${String(s.httpResponsesOther)} · wall p50 ${String(s.roundMedianMs)}ms p95 ${String(s.roundP95Ms)}ms · ${String(s.totalWallMs)}ms total`,
        "",
    ];
    return lines.join("\n");
}

/** Multi-line text you can read at a glance after a run. */
export function formatStressRunSummary(s: StressRunSummary): string {
    const avgWallPerBurst =
        s.burstCount > 0 ? Math.round(s.totalWallMs / s.burstCount) : 0;
    const overallRps =
        s.totalWallMs > 0
            ? (s.httpRequestsCompleted / s.totalWallMs) * 1000
            : 0;
    const avgOpsPerBurst =
        s.burstCount > 0
            ? Math.round(s.httpRequestsCompleted / s.burstCount)
            : 0;

    const runDesc =
        s.shutDownReason === "interrupt"
            ? `Stopped manually (Ctrl+C) after ${String(s.burstCount)} flood wall(s).`
            : `Finished ${String(s.burstCount)} planned flood wall(s).`;

    const lines = [
        "",
        "── Spire stress run — done ─────────────────────────────────────",
        "",
        `  ${runDesc}`,
        `  Target      ${s.host}`,
        `  Load shape  ${scenarioPlainEnglish(s.scenario)}`,
        `  Clients     ${String(s.clientCount)} libvex client(s)`,
        `  Concurrency last knob value  ${String(s.lastConcurrency)} parallel ops per client per wall (started at ${String(s.concurrencySnapshot)})`,
        "",
        `  Walls       ${String(s.burstCount)}  ·  ~${String(avgOpsPerBurst)} completed ops per wall (all clients, varies by scenario)`,
        `  HTTP-ish ops counted  ${String(s.httpRequestsCompleted)} (best-effort; libvex may batch or overlap WebSocket work)`,
        `  Wall clock  ${String(s.totalWallMs)} ms for the whole run`,
        `  Avg / wall  ~${String(avgWallPerBurst)} ms wall`,
        "",
        "  Wall timing (wall clock for each synchronized flood wall across all clients):",
        `    median    ${String(s.roundMedianMs)} ms`,
        `    p95       ${String(s.roundP95Ms)} ms`,
        "",
        `  Rough throughput  ~${overallRps.toFixed(0)} counted ops / second (stress client view)`,
        "",
        `  HTTP tally   ok ${String(s.httpResponsesOk)}  other_errors ${String(s.httpResponsesOther)}  status_histogram ${JSON.stringify(s.httpResponsesByStatus)}`,
        "",
        "  How to read this:",
        "    • Web UI (default) shows each libvex API facet under test; terminal stderr is for per-wall logs. SPIRE_STRESS_TUI=1 restores the full-screen TUI.",
        "    • If median wall time rises as you raise concurrency, you are finding the knee of the curve for your stack.",
        "",
        "  Default: run until Ctrl+C.  SPIRE_STRESS_ROUNDS=N  exit after N flood walls.  SPIRE_STRESS_SCENARIO=mixed|chat|noise.",
        "  SPIRE_STRESS_JSON=1  append JSON.  SPIRE_STRESS_WEB=0  no browser UI.  SPIRE_STRESS_PLAIN=1  no TUI.",
        "────────────────────────────────────────────────────────────────",
    ];
    return lines.join("\n");
}

export function writeStressRunSummary(
    s: StressRunSummary,
    options?: {
        readonly facetSnapshot?: StressUiSnapshot | null;
        readonly quiet?: boolean;
    },
): void {
    if (options?.quiet === true) {
        process.stdout.write(formatStressRunSummaryQuiet(s));
    } else {
        process.stdout.write(formatStressRunSummary(s));
    }
    if (process.env["SPIRE_STRESS_JSON"] === "1") {
        const payload: Record<string, unknown> = {
            burstCount: s.burstCount,
            clientCount: s.clientCount,
            concurrencySnapshot: s.concurrencySnapshot,
            host: s.host,
            httpRequestsCompleted: s.httpRequestsCompleted,
            http_responses_by_status: s.httpResponsesByStatus,
            http_responses_ok: s.httpResponsesOk,
            http_responses_other: s.httpResponsesOther,
            lastConcurrency: s.lastConcurrency,
            p50_ms: s.roundMedianMs,
            p95_ms: s.roundP95Ms,
            scenario: s.scenario,
            shutDownReason: s.shutDownReason,
            total_wall_ms: s.totalWallMs,
        };
        const snap = options?.facetSnapshot;
        if (snap !== undefined && snap !== null) {
            payload["facets"] = snap.facets.map((f) => ({
                apiCall: f.apiCall,
                fail: f.fail,
                group: f.group,
                id: f.id,
                ok: f.ok,
                protocolPath: f.protocolPath,
                status: f.status,
                title: f.title,
                total: f.ok + f.fail,
            }));
        }
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    }
}
