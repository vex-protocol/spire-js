/**
 * Human-readable final report for the Spire stress harness.
 * Set SPIRE_STRESS_JSON=1 to also print a machine-readable JSON block.
 */
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
    options?: { readonly quiet?: boolean },
): void {
    if (options?.quiet === true) {
        process.stdout.write(formatStressRunSummaryQuiet(s));
    } else {
        process.stdout.write(formatStressRunSummary(s));
    }
    if (process.env["SPIRE_STRESS_JSON"] === "1") {
        process.stdout.write(
            JSON.stringify(
                {
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
                },
                null,
                2,
            ) + "\n",
        );
    }
}
