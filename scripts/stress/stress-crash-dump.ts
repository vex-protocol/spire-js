/**
 * When libvex or Node throws outside our try/catch (e.g. WS timers), print
 * harness context to stderr so runs are debuggable.
 */
import type { StressClientViz } from "./stress-client-viz.ts";
import type { StressTraceDb } from "./stress-trace-db.ts";

import {
    STRESS_ISSUE_BUNDLE_PATH,
    buildFatalIssueBundle,
    writeFatalIssueBundle,
} from "./stress-issue-bundle.ts";

export interface StressCrashContext {
    chatWorld: null | { channelID: string; serverID: string };
    clientCount: number;
    clientViz: StressClientViz[] | null;
    currentBurst: number;
    host: string;
    lastConcurrency: number;
    noiseWorld: null | { channelID: string; serverID: string };
    phase: string;
    scenario: string;
}

function formatClientRows(viz: StressClientViz[] | null): string {
    if (viz === null || viz.length === 0) {
        return "  (no per-client viz — use scenario=noise for in-flight labels)\n";
    }
    const lines: string[] = [];
    for (let i = 0; i < viz.length; i++) {
        const v = viz[i];
        if (v === undefined) {
            continue;
        }
        const active = v.inFlight.length > 0 ? v.inFlight : v.lastOp;
        lines.push(
            `  #${String(i)}  active/last=${active.slice(0, 28)}  ok=${String(v.lastOk)}  ops=${String(v.ops)}  last_done=${v.lastOp.slice(0, 20)}`,
        );
    }
    return `${lines.join("\n")}\n`;
}

/** JSON-safe snapshot for SQLite / incident rows. */
export function stressHarnessSnapshot(
    ctx: StressCrashContext,
): Record<string, unknown> {
    const clients =
        ctx.clientViz?.map((v, i) => ({
            i,
            inFlight: v.inFlight,
            lastOk: v.lastOk,
            lastOp: v.lastOp,
            ops: v.ops,
        })) ?? null;
    return {
        burst: ctx.currentBurst,
        clientCount: ctx.clientCount,
        clients,
        concurrency: ctx.lastConcurrency,
        host: ctx.host,
        chatWorld: ctx.chatWorld,
        noiseWorld: ctx.noiseWorld,
        phase: ctx.phase,
        scenario: ctx.scenario,
    };
}

function formatNoise(world: StressCrashContext["noiseWorld"]): string {
    if (world === null) {
        return "";
    }
    return `  noise server ${world.serverID.slice(0, 12)}…  channel ${world.channelID.slice(0, 12)}…\n`;
}

function formatChatWorld(world: StressCrashContext["chatWorld"]): string {
    if (world === null) {
        return "";
    }
    return `  chat server ${world.serverID.slice(0, 12)}…  channel ${world.channelID.slice(0, 12)}…\n`;
}

export function formatStressCrashDump(
    ctx: StressCrashContext,
    err: unknown,
    kind: "uncaughtException" | "unhandledRejection",
): string {
    const msg = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error ? (err.stack ?? msg) : msg;
    return [
        "",
        "── spire-stress: fatal context ─────────────────────────────────",
        `  kind        ${kind}`,
        `  message     ${msg}`,
        `  phase       ${ctx.phase}`,
        `  burst       ${String(ctx.currentBurst)}`,
        `  concurrency ${String(ctx.lastConcurrency)}`,
        `  scenario    ${ctx.scenario}`,
        `  host        ${ctx.host}`,
        `  clients     ${String(ctx.clientCount)}`,
        formatNoise(ctx.noiseWorld),
        formatChatWorld(ctx.chatWorld),
        "  per-client (inFlight = op currently running on that client):",
        formatClientRows(ctx.clientViz),
        "  related_data (no root-cause guesses):",
        `    • On fatal, a JSON bundle is written to: ${STRESS_ISSUE_BUNDLE_PATH}`,
        "      (harness snapshot + error + telemetry slice + correlated failure groups).",
        "    • If SPIRE_STRESS_TRACE is enabled, see SQLite table incidents (harness_snapshot_json, recent_events_json).",
        "    • Optional: NODE_OPTIONS='--trace-uncaught' for Node async stack hints.",
        "    • Repo file index for LLM context: npm run stress:repo-manifest",
        "────────────────────────────────────────────────────────────────",
        "",
        stack,
        "",
    ].join("\n");
}

/** Register process hooks; call the returned function on clean shutdown. */
export function installStressCrashDiagnostics(
    ctx: StressCrashContext,
    options?: {
        readonly getTelemetrySnapshot?: () => unknown;
        readonly trace?: StressTraceDb | null;
    },
): () => void {
    const trace = options?.trace ?? null;
    const getTelemetrySnapshot = options?.getTelemetrySnapshot;
    const onUncaught = (err: Error) => {
        const harness = stressHarnessSnapshot(ctx);
        process.stderr.write(
            formatStressCrashDump(ctx, err, "uncaughtException"),
        );
        trace?.captureFatal({
            harnessSnapshot: harness,
            kind: "uncaughtException",
            reason: err,
        });
        try {
            const bundle = buildFatalIssueBundle({
                run: harness,
                kind: "uncaughtException",
                reason: err,
                telemetrySnapshot: getTelemetrySnapshot?.() ?? null,
            });
            const path = writeFatalIssueBundle(bundle);
            process.stderr.write(`  issue_bundle  ${path}\n`);
        } catch {
            /* ignore bundle write errors */
        }
    };
    const onUnhandled = (reason: unknown) => {
        const harness = stressHarnessSnapshot(ctx);
        process.stderr.write(
            formatStressCrashDump(ctx, reason, "unhandledRejection"),
        );
        trace?.captureFatal({
            harnessSnapshot: harness,
            kind: "unhandledRejection",
            reason,
        });
        try {
            const bundle = buildFatalIssueBundle({
                run: harness,
                kind: "unhandledRejection",
                reason,
                telemetrySnapshot: getTelemetrySnapshot?.() ?? null,
            });
            const path = writeFatalIssueBundle(bundle);
            process.stderr.write(`  issue_bundle  ${path}\n`);
        } catch {
            /* ignore bundle write errors */
        }
    };
    process.on("uncaughtException", onUncaught);
    process.on("unhandledRejection", onUnhandled);
    return () => {
        process.off("uncaughtException", onUncaught);
        process.off("unhandledRejection", onUnhandled);
    };
}
