/**
 * Local stress harness against a running Spire.
 *
 * Prerequisites:
 * - Same `DEV_API_KEY` on Spire and in env; sent as `x-dev-api-key` (rate-limit bypass).
 * - `NODE_ENV` must be `development` or `test` for libvex `unsafeHttp` (forced when unset).
 *
 * @example Default — RNG “noise” across libvex (10 clients, shared server, invites, DMs, WS):
 *   DEV_API_KEY=secret npm run stress:web
 *   Opens http://127.0.0.1:18777/ by default in your browser (SPIRE_STRESS_OPEN_BROWSER=0 to skip).
 *
 * @example Lighter read-only mix (no multi-user noise world):
 *   SPIRE_STRESS_SCENARIO=mixed DEV_API_KEY=secret npm run stress:web
 *
 * @example Chat-shaped load (WebSocket + shared server, group/DM + history reads):
 *   SPIRE_STRESS_SCENARIO=chat DEV_API_KEY=secret npm run stress:web
 *
 * @example Finite run — exit after N flood walls:
 *   SPIRE_STRESS_ROUNDS=25 DEV_API_KEY=secret npm run stress:web
 *
 * @example Reuse one account (do not use with default `noise`; use `mixed` or `chat`):
 *   SPIRE_STRESS_SCENARIO=mixed SPIRE_STRESS_USERNAME=alice SPIRE_STRESS_PASSWORD='…' npm run stress:web
 *
 * Trace SQLite (harness steps + fatals): default ~/.spire-stress/traces.sqlite — disable with SPIRE_STRESS_TRACE=0,
 * or set SPIRE_STRESS_TRACE_DB=/path/to/file.sqlite
 *
 * Optional success request ring (sanitized inputs for last ~80 ops): SPIRE_STRESS_LOG_REQUESTS=1
 *
 * Wall pacing (`SPIRE_STRESS_LOAD_MODE`): canonical **`immediate`** (start the next flood wall as soon as
 * the previous finishes) or **`paced`** (sleep `SPIRE_STRESS_BURST_GAP_MS`, default 750, between walls).
 * Legacy **`continuous`** and **`burst`** are still accepted as aliases for `immediate` and `paced`.
 * Each “wall” is still one synchronized `Promise.all` over all slots — only the idle gap between walls changes.
 *
 * Bisecting limits: each stderr `[stress] wall` line includes offered≈slots/s (logical slot completions ×1000/wall_ms).
 * That is not raw HTTP RPS — noise/chat often do several requests per slot. Scale SPIRE_STRESS_CLIENTS and
 * SPIRE_STRESS_CONCURRENCY gradually while watching Spire CPU and this number.
 *
 * Time cap (stress:cli matrix / unattended soak): SPIRE_STRESS_MAX_WALL_SEC=N stops the flood loop after N seconds
 * of wall time (flood walls + any paced idle gaps). Works with SPIRE_STRESS_FOREVER=1. See npm run stress:cli.
 *
 * Web dashboard: POST /api/restart-run queues a full session restart (clients + load mode + concurrency)
 * after the current flood wall (see Session controls in scripts/stress/web/index.html).
 *
 * CLI: `node …/spire-stress.ts --help` · `SPIRE_STRESS_WEB=0` skips the long banner; each flood wall prints one
 * dashboard-style line to stderr (scenario, target, wall#, pacing, clients, slots/s, ops, …). Full noisy stderr:
 * `SPIRE_STRESS_VERBOSE=1`.
 */

import type { Client } from "@vex-chat/libvex";

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import readline from "node:readline";

import axios from "axios";
import { config } from "dotenv";

import { DEV_API_KEY_HEADER } from "../../src/server/rateLimit.ts";

import {
    bootstrapChatWorld,
    oneChatBurst,
    type ChatWorld,
} from "./stress-chat.ts";
import { createStressClientViz } from "./stress-client-viz.ts";
import {
    installStressCrashDiagnostics,
    type StressCrashContext,
} from "./stress-crash-dump.ts";
import { StressDashboard } from "./stress-dashboard.ts";
import {
    createHttpExpectStats,
    httpFailureTotal,
    type HttpExpectStats,
    recordHttpFailure,
} from "./stress-http-stats.ts";
import { StressKnobs } from "./stress-knobs.ts";
import {
    parseStressLoadPacing,
    type StressLoadPacing,
} from "./stress-load-pacing.ts";
import {
    bootstrapNoiseWorld,
    runNoiseBurst,
    type NoiseWorld,
} from "./stress-noise.ts";
import {
    isLikelySpireDown,
    isWrappedSpireUnreachable,
    wrapSpireUnreachable,
} from "./stress-reachability.ts";
import { StressRestartQueue } from "./stress-restart-queue.ts";
import {
    type StressRunSummary,
    writeStressRunSummary,
} from "./stress-summary.ts";
import {
    settleWithTelemetry,
    StressTelemetry,
    type TelemetryTouchCtx,
} from "./stress-telemetry.ts";
import {
    probeStressTraceDbPathForReading,
    StressTraceDb,
} from "./stress-trace-db.ts";
import { startStressWebServer } from "./stress-web-server.ts";

/** libvex / `ws` attach many `"message"` handlers; default (10) spams MaxListenersExceededWarning. */
EventEmitter.defaultMaxListeners = 100;

function sleepMs(ms: number): Promise<void> {
    return new Promise((resolve) => {
        setTimeout(resolve, ms);
    });
}

/** One stderr line per wall when `SPIRE_STRESS_WEB=0` — mirrors the web stats strip (dashboard). */
function writeStressCliWallSnapshot(p: {
    readonly burstGapMs: number;
    readonly clients: number;
    readonly concurrency: number;
    readonly host: string;
    readonly lastWallMs: number;
    readonly loadPacing: StressLoadPacing;
    readonly offeredSlotsPerSec: number;
    readonly opsCounted: number;
    readonly phase: string;
    readonly scenario: string;
    readonly wallIndex: number;
    readonly wallTotal: number | null;
}): void {
    const wall =
        p.wallTotal === null
            ? String(p.wallIndex)
            : `${String(p.wallIndex)}/${String(p.wallTotal)}`;
    const pacedGap =
        p.loadPacing === "paced" && p.burstGapMs > 0
            ? `${String(p.burstGapMs)}ms`
            : "—";
    process.stderr.write(
        [
            "[stress]",
            `scenario=${p.scenario}`,
            `target=${p.host}`,
            `phase=${p.phase}`,
            `wall#=${wall}`,
            `pacing=${p.loadPacing}`,
            `pacedGap=${pacedGap}`,
            `conc=${String(p.concurrency)}`,
            `clients=${String(p.clients)}`,
            `lastWallSlots/s≈${String(p.offeredSlotsPerSec)}`,
            `opsCounted=${String(p.opsCounted)}`,
            `lastWall=${String(p.lastWallMs)}ms`,
        ].join("  ") + "\n",
    );
}

async function oneReadBurst(
    client: Client,
    scenario: string,
    n: number,
    stats: HttpExpectStats,
    telemetry: StressTelemetry | null,
    phase: string,
    burst: number,
): Promise<void> {
    const ctx = (clientIndex?: number): TelemetryTouchCtx => ({
        burst,
        clientIndex,
        phase,
    });
    switch (scenario) {
        case "whoami":
            await Promise.all(
                Array.from({ length: n }, (_, i) =>
                    settleWithTelemetry(
                        stats,
                        telemetry,
                        "Client.whoami | read",
                        ctx(i),
                        client.whoami(),
                        { inputs: { clientSlot: i } },
                    ),
                ),
            );
            return;
        case "servers":
            await Promise.all(
                Array.from({ length: n }, (_, i) =>
                    settleWithTelemetry(
                        stats,
                        telemetry,
                        "Client.servers.retrieve | read",
                        ctx(i),
                        client.servers.retrieve(),
                        { inputs: { clientSlot: i } },
                    ),
                ),
            );
            return;
        default:
            await Promise.all(
                Array.from({ length: n }, (_, i) =>
                    i % 2 === 0
                        ? settleWithTelemetry(
                              stats,
                              telemetry,
                              "Client.servers.retrieve | read",
                              ctx(i),
                              client.servers.retrieve(),
                              { inputs: { clientSlot: i, branch: "servers" } },
                          )
                        : settleWithTelemetry(
                              stats,
                              telemetry,
                              "Client.permissions.retrieve | read",
                              ctx(i),
                              client.permissions.retrieve(),
                              {
                                  inputs: {
                                      clientSlot: i,
                                      branch: "permissions",
                                  },
                              },
                          ),
                ),
            );
    }
}

/** Returns number of logical operations awaited (per client slot). */
async function runBurstForAllClients(
    clients: Client[],
    scenario: string,
    perClientConcurrency: number,
    chatWorld: ChatWorld | null,
    stats: HttpExpectStats,
    noiseWorld: NoiseWorld | null,
    clientViz: ReturnType<typeof createStressClientViz> | null,
    trace: StressTraceDb | null,
    crashCtx: StressCrashContext,
    telemetry: StressTelemetry | null,
): Promise<number> {
    if (scenario === "noise") {
        if (noiseWorld === null || clientViz === null) {
            throw new Error("noise scenario requires world + client viz.");
        }
        await runNoiseBurst(
            clients,
            noiseWorld,
            perClientConcurrency,
            stats,
            clientViz,
            trace,
            crashCtx,
            telemetry,
        );
        return clients.length * perClientConcurrency;
    }
    if (scenario === "chat") {
        if (chatWorld === null) {
            throw new Error("chat scenario requires a shared ChatWorld.");
        }
        await Promise.all(
            clients.map((c, i) =>
                oneChatBurst(
                    c,
                    i,
                    chatWorld,
                    perClientConcurrency,
                    stats,
                    telemetry,
                    crashCtx.phase,
                    crashCtx.currentBurst,
                ),
            ),
        );
        return clients.length * perClientConcurrency;
    }
    await Promise.all(
        clients.map((c) =>
            oneReadBurst(
                c,
                scenario,
                perClientConcurrency,
                stats,
                telemetry,
                crashCtx.phase,
                crashCtx.currentBurst,
            ),
        ),
    );
    return clients.length * perClientConcurrency;
}

async function bootstrapClient(
    host: string,
    scenario: string,
    stats: HttpExpectStats,
    telemetry: StressTelemetry | null,
    phase: string,
    burst: number,
): Promise<Client> {
    try {
        const { Client } = await import("@vex-chat/libvex");
        const dbFolder = join(tmpdir(), `spire-stress-${randomUUID()}`);
        mkdirSync(dbFolder, { recursive: true });

        const bootCtx: TelemetryTouchCtx = { burst, phase };

        const c = await settleWithTelemetry(
            stats,
            telemetry,
            "Client.create",
            bootCtx,
            Client.create(undefined, {
                dbFolder,
                devApiKey: process.env["DEV_API_KEY"]?.trim() || undefined,
                host,
                inMemoryDb: true,
                unsafeHttp: true,
            }),
            {
                inputs: {
                    dbFolder: basename(dbFolder),
                    host,
                    inMemoryDb: true,
                    unsafeHttp: true,
                },
            },
        );

        const existingUser = process.env["SPIRE_STRESS_USERNAME"];
        const existingPass = process.env["SPIRE_STRESS_PASSWORD"];

        if (existingUser !== undefined && existingUser.length > 0) {
            if (existingPass === undefined) {
                throw new Error(
                    "SPIRE_STRESS_PASSWORD is required when SPIRE_STRESS_USERNAME is set.",
                );
            }
            const loginRes = await c.login(existingUser, existingPass);
            if (!loginRes.ok) {
                const fail = new Error(loginRes.error ?? "login failed");
                recordHttpFailure(stats, fail);
                telemetry?.touchFail(
                    "Client.login",
                    {
                        ...bootCtx,
                        requestInputs: {
                            mode: "existing_user",
                            username: existingUser,
                        },
                    },
                    fail,
                );
                throw fail;
            }
            stats.ok += 1;
            telemetry?.touchOk("Client.login", {
                ...bootCtx,
                requestInputs: {
                    mode: "existing_user",
                    username: existingUser,
                },
            });
        } else {
            const password =
                process.env["SPIRE_STRESS_REGISTER_PASSWORD"] ??
                "StressPassw0rd!localonly";
            const username = Client.randomUsername();
            const [, regErr] = await c.register(username, password);
            if (regErr) {
                recordHttpFailure(stats, regErr);
                telemetry?.touchFail(
                    "Client.register",
                    {
                        ...bootCtx,
                        requestInputs: {
                            passwordLength: password.length,
                            username,
                        },
                    },
                    regErr,
                );
                throw regErr;
            }
            stats.ok += 1;
            telemetry?.touchOk("Client.register", {
                ...bootCtx,
                requestInputs: {
                    passwordLength: password.length,
                    username,
                },
            });
            const loginRes = await c.login(username, password);
            if (!loginRes.ok) {
                const fail = new Error(
                    loginRes.error ?? "login after register failed",
                );
                recordHttpFailure(stats, fail);
                telemetry?.touchFail(
                    "Client.login",
                    {
                        ...bootCtx,
                        requestInputs: {
                            mode: "after_register",
                            passwordLength: password.length,
                            username,
                        },
                    },
                    fail,
                );
                throw fail;
            }
            stats.ok += 1;
            telemetry?.touchOk("Client.login", {
                ...bootCtx,
                requestInputs: {
                    mode: "after_register",
                    passwordLength: password.length,
                    username,
                },
            });
        }

        const wantWs =
            scenario === "chat" || process.env["SPIRE_STRESS_WS"] === "1";
        if (wantWs) {
            await settleWithTelemetry(
                stats,
                telemetry,
                "Client.connect",
                bootCtx,
                c.connect(),
                { inputs: { scenario, ws: true } },
            );
        }

        return c;
    } catch (err: unknown) {
        if (isWrappedSpireUnreachable(err)) {
            throw err;
        }
        if (isLikelySpireDown(err)) {
            throw wrapSpireUnreachable(host, err);
        }
        throw err;
    }
}

function httpStatusBase(host: string): string {
    const trimmed = host.trim();
    if (/^https?:\/\//i.test(trimmed)) {
        return trimmed.replace(/\/$/, "");
    }
    return `http://${trimmed}`;
}

/** Open the dashboard URL in the system default browser (no extra npm deps). */
function openStressDashboardInBrowser(url: string): void {
    const child =
        process.platform === "darwin"
            ? spawn("open", [url], { detached: true, stdio: "ignore" })
            : process.platform === "win32"
              ? spawn("cmd", ["/c", "start", "", url], {
                    detached: true,
                    shell: false,
                    stdio: "ignore",
                })
              : spawn("xdg-open", [url], { detached: true, stdio: "ignore" });
    child.unref();
}

function attachStdinTuning(
    knobsRef: { knobs: StressKnobs },
    getTelemetry: () => StressTelemetry | null,
    requestShutdown: () => void,
): () => void {
    if (!process.stdin.isTTY) {
        return () => {};
    }
    readline.emitKeypressEvents(process.stdin);
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);

    const onKeypress = (_str: string, key: readline.Key | undefined): void => {
        if (!key) {
            return;
        }
        if (key.ctrl && key.name === "c") {
            /* Raw mode: Ctrl+C is a keypress; SIGINT is unreliable — same as q. */
            requestShutdown();
            return;
        }
        if (key.name === "q") {
            requestShutdown();
            return;
        }
        if (key.name === "+" || key.name === "=") {
            knobsRef.knobs.up(key.shift ? 50 : 10);
            getTelemetry()?.setConcurrency(knobsRef.knobs.concurrency);
            return;
        }
        if (key.name === "-") {
            knobsRef.knobs.down(key.shift ? 50 : 10);
            getTelemetry()?.setConcurrency(knobsRef.knobs.concurrency);
            return;
        }
        if (key.name === "0") {
            knobsRef.knobs.reset();
            getTelemetry()?.setConcurrency(knobsRef.knobs.concurrency);
        }
    };

    process.stdin.on("keypress", onKeypress);
    return () => {
        process.stdin.off("keypress", onKeypress);
        process.stdin.setRawMode(wasRaw);
    };
}

function printSpireStressCliHelp(): void {
    process.stdout.write(
        [
            "spire-stress — libvex clients against a running Spire",
            "",
            "Requires DEV_API_KEY (same value as on the Spire process).",
            "",
            "Environment (common):",
            "  SPIRE_STRESS_HOST              default 127.0.0.1:16777",
            "  SPIRE_STRESS_SCENARIO          mixed | noise | chat | …",
            "  SPIRE_STRESS_CLIENTS           default 10",
            "  SPIRE_STRESS_CONCURRENCY       parallel ops per client per wall",
            "  SPIRE_STRESS_ROUNDS=N          exit after N flood walls",
            "  SPIRE_STRESS_FOREVER=0         finite run (default 10 walls if ROUNDS unset)",
            "  SPIRE_STRESS_MAX_WALL_SEC      wall-time cap when FOREVER=1",
            "  SPIRE_STRESS_WEB=0             no web UI; quiet stderr unless SPIRE_STRESS_VERBOSE=1",
            "  SPIRE_STRESS_JSON=1            append JSON summary to stdout",
            "",
            "npm run stress:web   ·   npm run stress:cli (headless matrix)",
            "",
        ].join("\n"),
    );
}

async function main(): Promise<void> {
    config();

    const argv = process.argv.slice(2);
    if (argv.includes("--help") || argv.includes("-h")) {
        printSpireStressCliHelp();
        process.exit(0);
    }

    if (
        process.env["NODE_ENV"] !== "development" &&
        process.env["NODE_ENV"] !== "test"
    ) {
        process.env["NODE_ENV"] = "development";
    }

    const devApiKey = process.env["DEV_API_KEY"]?.trim() ?? "";
    if (devApiKey.length === 0) {
        process.stderr.write(
            "DEV_API_KEY is required (must match the value set on the Spire process).\n",
        );
        process.exit(1);
    }

    // Stress-only axios (status probes, etc.). libvex uses its own instance — pass
    // `devApiKey` in `Client.create` options so Spire sees `x-dev-api-key` on API traffic.
    axios.defaults.headers.common[DEV_API_KEY_HEADER] = devApiKey;

    const host = process.env["SPIRE_STRESS_HOST"] ?? "127.0.0.1:16777";
    const initialConcurrency = Math.max(
        1,
        Number(process.env["SPIRE_STRESS_CONCURRENCY"] ?? "25"),
    );
    const roundsRaw = process.env["SPIRE_STRESS_ROUNDS"];
    const roundsTrim = typeof roundsRaw === "string" ? roundsRaw.trim() : "";
    const roundsParsed = roundsTrim === "" ? Number.NaN : Number(roundsTrim);
    const finiteBurstCount =
        Number.isFinite(roundsParsed) && roundsParsed > 0
            ? Math.max(1, Math.floor(roundsParsed))
            : null;
    const foreverExplicitOff =
        process.env["SPIRE_STRESS_FOREVER"] === "0" ||
        process.env["SPIRE_STRESS_FOREVER"] === "false";

    let forever: boolean;
    let plannedRounds: number;
    if (finiteBurstCount !== null) {
        forever = false;
        plannedRounds = finiteBurstCount;
    } else if (foreverExplicitOff) {
        forever = false;
        plannedRounds = 10;
    } else {
        forever = true;
        plannedRounds = 0;
    }

    const scenario = process.env["SPIRE_STRESS_SCENARIO"] ?? "noise";
    const clientCount = Math.max(
        1,
        Number(process.env["SPIRE_STRESS_CLIENTS"] ?? "10"),
    );

    const loadPacing = parseStressLoadPacing(
        process.env["SPIRE_STRESS_LOAD_MODE"] ?? "",
    );
    const burstGapMsParsed = Number(
        process.env["SPIRE_STRESS_BURST_GAP_MS"] ?? "750",
    );
    const burstGapMs =
        loadPacing === "paced"
            ? Math.max(
                  0,
                  Number.isFinite(burstGapMsParsed)
                      ? Math.floor(burstGapMsParsed)
                      : 750,
              )
            : 0;

    const maxWallSecRaw =
        process.env["SPIRE_STRESS_MAX_WALL_SEC"]?.trim() ?? "";
    const maxWallSecParsed = Number(maxWallSecRaw);
    const maxWallMs =
        maxWallSecRaw !== "" &&
        Number.isFinite(maxWallSecParsed) &&
        maxWallSecParsed > 0
            ? Math.floor(maxWallSecParsed * 1000)
            : null;

    if (scenario === "noise") {
        const reuse = process.env["SPIRE_STRESS_USERNAME"]?.trim() ?? "";
        if (reuse.length > 0) {
            process.stderr.write(
                "SPIRE_STRESS_SCENARIO=noise needs a distinct libvex user per client. Unset SPIRE_STRESS_USERNAME (and SPIRE_STRESS_PASSWORD), or pick scenario=mixed / chat.\n",
            );
            process.exit(1);
        }
    }

    /** Headless (`SPIRE_STRESS_WEB=0`): minimal stderr + compact summary unless VERBOSE=1. */
    const stressQuietCli =
        process.env["SPIRE_STRESS_WEB"] === "0" &&
        process.env["SPIRE_STRESS_VERBOSE"] !== "1";

    const knobsRef = { knobs: new StressKnobs(initialConcurrency) };
    /** Ref object; read stop via `stressRunShouldStop()` so async loops are not wrongly narrowed. */
    const runFlags = { interrupted: false, stop: false };
    const stressRunShouldStop = (): boolean => runFlags.stop;
    const telemetryRef = { current: null as StressTelemetry | null };
    const detachStdin = forever
        ? attachStdinTuning(
              knobsRef,
              () => telemetryRef.current,
              () => {
                  runFlags.stop = true;
                  runFlags.interrupted = true;
              },
          )
        : () => {};
    const onSignal = (): void => {
        runFlags.stop = true;
        runFlags.interrupted = true;
    };
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);

    const bannerLines = [
        "",
        "Spire stress — starting (libvex clients hammering your Spire).",
        `  Target     ${host}`,
        `  Run        ${forever ? "until Ctrl+C (or q)" : `${String(plannedRounds)} flood wall(s) then exit`}`,
        `  Wall pace  ${loadPacing}${loadPacing === "paced" && burstGapMs > 0 ? ` · ${String(burstGapMs)} ms idle between walls` : loadPacing === "paced" ? " · gap 0 ms" : ""}`,
        `  Scenario   ${scenario}  ·  clients ${String(clientCount)}  ·  starting ${String(initialConcurrency)} parallel ops per client per wall`,
        forever
            ? "  Tuning     Web UI + TTY: +/−/0 knobs, q or Ctrl+C to stop. SPIRE_STRESS_TUI=1 restores the full-screen terminal dashboard."
            : "  Tuning     set SPIRE_STRESS_CONCURRENCY before launch, or use SPIRE_STRESS_ROUNDS for a finite wall count (see SPIRE_STRESS_FOREVER).",
        ...(maxWallMs !== null
            ? [
                  `  Wall cap   SPIRE_STRESS_MAX_WALL_SEC=${maxWallSecRaw}s — flood stops after that much wall time (walls + paced idle only).`,
              ]
            : []),
        "  Web UI     SPIRE_STRESS_WEB=0 disables UI. SPIRE_STRESS_UI_PORT=18777  ·  SPIRE_STRESS_OPEN_BROWSER=0 skips opening the default browser",
        "  Target down  Exit code 2 + framed stderr message when Spire is not reachable (wrong SPIRE_STRESS_HOST or server not started).",
        "  Crashes    uncaught → stderr context dump (burst, clients). NODE_OPTIONS='--trace-uncaught' for async stacks.",
        "  Trace      harness_events + incidents in SQLite (see header SPIRE_STRESS_TRACE*).",
        "  Throughput stderr lines: offered≈slots/s = ops×1000/wall_ms (see file header; not HTTP RPS).",
        "",
    ];
    if (!stressQuietCli) {
        process.stderr.write(bannerLines.join("\n"));
    } else {
        const runDesc = forever
            ? maxWallMs !== null
                ? `open-ended · cap ${maxWallSecRaw}s wall time`
                : "open-ended"
            : `${String(plannedRounds)} walls`;
        process.stderr.write(
            `spire-stress · ${host} · ${scenario} · ${String(clientCount)} clients · ${runDesc}\n`,
        );
    }

    const crashCtx: StressCrashContext = {
        chatWorld: null,
        clientCount,
        clientViz: null,
        currentBurst: 0,
        host,
        lastConcurrency: initialConcurrency,
        noiseWorld: null,
        phase: "init",
        scenario,
    };
    const trace = StressTraceDb.tryOpenFromEnv();
    if (trace !== null && !stressQuietCli) {
        process.stderr.write(
            `  Trace DB   ${trace.getDbPathForDisplay()}  run_id=${trace.getRunId()}\n`,
        );
    }
    const uninstallCrashDump = installStressCrashDiagnostics(crashCtx, {
        getTelemetrySnapshot: () => telemetryRef.current?.getSnapshot() ?? null,
        trace,
    });

    let traceEndedReason = "unknown";
    const traceSummary: Record<string, unknown> = { status: "incomplete" };
    let webHandle: Awaited<ReturnType<typeof startStressWebServer>> | null =
        null;

    try {
        trace?.beginRun({ clientCount, host, scenario });
        trace?.append({
            burst: 0,
            detail: { initialConcurrency },
            event: "run_start",
            phase: "init",
        });

        const restartQueue = new StressRestartQueue();
        let sessionClientCount = clientCount;
        let sessionLoadPacing = loadPacing;
        let sessionBurstGapMs = burstGapMs;

        const webEnabled = process.env["SPIRE_STRESS_WEB"] !== "0";
        const telemetry = webEnabled ? new StressTelemetry(scenario) : null;
        const uiPortRaw = process.env["SPIRE_STRESS_UI_PORT"] ?? "18777";
        const uiPortParsed = Number(uiPortRaw);
        const uiPort =
            Number.isFinite(uiPortParsed) &&
            uiPortParsed >= 1 &&
            uiPortParsed <= 65_535
                ? Math.floor(uiPortParsed)
                : 18_777;
        if (telemetry !== null) {
            telemetryRef.current = telemetry;
            telemetry.setRunBanner({
                burstGapMs: sessionBurstGapMs,
                clientCount: sessionClientCount,
                concurrency: knobsRef.knobs.concurrency,
                forever,
                host,
                loadPacing: sessionLoadPacing,
                plannedRounds,
            });
            webHandle = await startStressWebServer(telemetry, uiPort, {
                restartQueue,
                scenario,
            });
            const uiUrl = `http://127.0.0.1:${String(webHandle.port)}/`;
            process.stderr.write(`  Web UI     ${uiUrl}\n`);
            if (process.env["SPIRE_STRESS_OPEN_BROWSER"] !== "0") {
                try {
                    openStressDashboardInBrowser(uiUrl);
                } catch {
                    /* ignore missing open/xdg-open */
                }
            }
        }

        const useUi =
            process.env["SPIRE_STRESS_TUI"] === "1" &&
            process.stdout.isTTY &&
            process.env["SPIRE_STRESS_PLAIN"] !== "1";
        const statusBase = httpStatusBase(host);
        let dashboard: StressDashboard | null = null;

        let lastHttpStats: HttpExpectStats = createHttpExpectStats();
        let lastBurstWallMs: number[] = [];
        let lastBurst = 0;
        let lastCompletedHttpOps = 0;
        let lastSessionClientCount = sessionClientCount;

        sessionLoop: while (!stressRunShouldStop()) {
            const httpStats = createHttpExpectStats();
            const clientViz =
                scenario === "noise"
                    ? createStressClientViz(sessionClientCount)
                    : null;
            crashCtx.clientCount = sessionClientCount;
            crashCtx.clientViz = clientViz;
            crashCtx.chatWorld = null;
            crashCtx.noiseWorld = null;

            telemetry?.resetSessionForNewRun({
                burstGapMs: sessionBurstGapMs,
                clientCount: sessionClientCount,
                concurrency: knobsRef.knobs.concurrency,
                forever,
                host,
                loadPacing: sessionLoadPacing,
                plannedRounds,
            });
            telemetry?.setRestartPending(false);

            if (useUi) {
                if (dashboard !== null) {
                    dashboard.stop();
                }
                dashboard = new StressDashboard({
                    clientCount: sessionClientCount,
                    clientViz,
                    concurrencySnapshot: knobsRef.knobs.concurrency,
                    forever,
                    host,
                    httpStats,
                    knobs: forever ? knobsRef.knobs : null,
                    plannedRounds: forever ? 0 : plannedRounds,
                    scenario,
                    statusBaseUrl: statusBase,
                    traceLogPath:
                        trace !== null
                            ? trace.getDbPathForDisplay()
                            : probeStressTraceDbPathForReading(),
                });
                dashboard.start();
            }

            let completedHttpOps = 0;
            const burstWallMs: number[] = [];

            const clients: Client[] = [];
            crashCtx.phase = "bootstrap";
            telemetry?.setPhase("bootstrap");
            dashboard?.setState({ phase: "bootstrap", currentBurst: 0 });

            for (let i = 0; i < sessionClientCount; i++) {
                clients.push(
                    await bootstrapClient(
                        host,
                        scenario,
                        httpStats,
                        telemetry,
                        crashCtx.phase,
                        crashCtx.currentBurst,
                    ),
                );
            }
            trace?.append({
                burst: 0,
                detail: { step: "clients_bootstrapped", count: clients.length },
                event: "bootstrap",
                phase: crashCtx.phase,
            });

            const chatWorld: ChatWorld | null =
                scenario === "chat"
                    ? await bootstrapChatWorld(
                          clients,
                          httpStats,
                          telemetry,
                          crashCtx.phase,
                          crashCtx.currentBurst,
                      )
                    : null;
            if (chatWorld !== null) {
                crashCtx.chatWorld = {
                    channelID: chatWorld.channelID,
                    serverID: chatWorld.serverID,
                };
                trace?.append({
                    burst: 0,
                    detail: {
                        channelID: chatWorld.channelID,
                        clientCount: clients.length,
                        serverID: chatWorld.serverID,
                    },
                    event: "chat_world_ready",
                    phase: crashCtx.phase,
                });
            }

            const noiseWorld: NoiseWorld | null =
                scenario === "noise"
                    ? await bootstrapNoiseWorld(
                          clients,
                          httpStats,
                          trace,
                          crashCtx,
                          telemetry,
                      )
                    : null;
            if (noiseWorld !== null) {
                crashCtx.noiseWorld = {
                    channelID: noiseWorld.channelID,
                    serverID: noiseWorld.serverID,
                };
            }

            dashboard?.setState({ phase: "flood" });
            crashCtx.phase = "flood";
            telemetry?.setPhase("flood");

            let burst = 0;
            let sessionRestart = false;
            const floodWallStart = Date.now();

            const applyQueuedRestart = (): boolean => {
                if (restartQueue.peek() === null) {
                    return false;
                }
                const next = restartQueue.consume();
                if (next === null) {
                    return false;
                }
                sessionClientCount = next.clientCount;
                sessionLoadPacing = next.loadPacing;
                sessionBurstGapMs =
                    next.loadPacing === "paced"
                        ? Math.max(
                              0,
                              Math.min(
                                  300_000,
                                  Number.isFinite(Number(next.burstGapMs))
                                      ? Math.floor(Number(next.burstGapMs))
                                      : 750,
                              ),
                          )
                        : 0;
                knobsRef.knobs = new StressKnobs(
                    Math.max(1, Math.floor(next.concurrency)),
                );
                telemetry?.setConcurrency(knobsRef.knobs.concurrency);
                telemetry?.setRestartPending(false);
                return true;
            };

            if (forever) {
                floodForever: while (!stressRunShouldStop()) {
                    burst += 1;
                    const n = knobsRef.knobs.concurrency;
                    crashCtx.currentBurst = burst;
                    crashCtx.lastConcurrency = n;
                    dashboard?.setState({
                        currentBurst: burst,
                        inFlight: sessionClientCount * n,
                    });
                    const t0 = Date.now();
                    trace?.append({
                        burst,
                        detail: { concurrency: n, kind: "burst_begin" },
                        event: "burst",
                        phase: crashCtx.phase,
                    });
                    const ops = await runBurstForAllClients(
                        clients,
                        scenario,
                        n,
                        chatWorld,
                        httpStats,
                        noiseWorld,
                        clientViz,
                        trace,
                        crashCtx,
                        telemetry,
                    );
                    const dt = Date.now() - t0;
                    const offeredSlotsPerSec =
                        dt > 0 ? Math.round((ops * 1000) / dt) : 0;
                    trace?.append({
                        burst,
                        detail: {
                            concurrency: n,
                            dt_ms: dt,
                            kind: "burst_end",
                            offered_slots_per_sec: offeredSlotsPerSec,
                            ops,
                        },
                        event: "burst",
                        phase: crashCtx.phase,
                    });
                    burstWallMs.push(dt);
                    completedHttpOps += ops;
                    telemetry?.setBurstContext(burst, n);
                    telemetry?.setProgress(
                        completedHttpOps,
                        dt,
                        offeredSlotsPerSec,
                    );
                    dashboard?.setState({
                        completedHttpOps,
                        inFlight: 0,
                        lastBurstMs: dt,
                    });
                    if (stressQuietCli) {
                        writeStressCliWallSnapshot({
                            burstGapMs: sessionBurstGapMs,
                            clients: sessionClientCount,
                            concurrency: n,
                            host,
                            lastWallMs: dt,
                            loadPacing: sessionLoadPacing,
                            offeredSlotsPerSec,
                            opsCounted: completedHttpOps,
                            phase: crashCtx.phase,
                            scenario,
                            wallIndex: burst,
                            wallTotal: null,
                        });
                    } else if (telemetry !== null || !useUi) {
                        process.stderr.write(
                            `[stress] wall ${String(burst)}  ${String(dt)}ms wall  ops=${String(ops)}  conc=${String(n)}  offered≈${String(offeredSlotsPerSec)} slots/s\n`,
                        );
                    }
                    if (
                        maxWallMs !== null &&
                        Date.now() - floodWallStart >= maxWallMs
                    ) {
                        if (!stressQuietCli) {
                            process.stderr.write(
                                `[stress] wall cap SPIRE_STRESS_MAX_WALL_SEC=${maxWallSecRaw}s reached — stopping flood.\n`,
                            );
                        } else {
                            process.stderr.write(
                                `[stress] wall cap ${maxWallSecRaw}s wall time — stopping flood.\n`,
                            );
                        }
                        break floodForever;
                    }
                    if (applyQueuedRestart()) {
                        await Promise.all(clients.map((c) => c.close()));
                        sessionRestart = true;
                        if (!stressQuietCli) {
                            process.stderr.write(
                                "[stress] web: restarting with new parameters after flood wall.\n",
                            );
                        }
                        break floodForever;
                    }
                    if (
                        sessionLoadPacing === "paced" &&
                        sessionBurstGapMs > 0 &&
                        !stressRunShouldStop()
                    ) {
                        await sleepMs(sessionBurstGapMs);
                    }
                }
            } else {
                floodFinite: for (
                    let r = 0;
                    r < plannedRounds && !stressRunShouldStop();
                    r++
                ) {
                    burst = r + 1;
                    const n = knobsRef.knobs.concurrency;
                    crashCtx.currentBurst = burst;
                    crashCtx.lastConcurrency = n;
                    dashboard?.setState({
                        currentBurst: burst,
                        inFlight: sessionClientCount * n,
                    });
                    const t0 = Date.now();
                    trace?.append({
                        burst,
                        detail: { concurrency: n, kind: "burst_begin" },
                        event: "burst",
                        phase: crashCtx.phase,
                    });
                    const ops = await runBurstForAllClients(
                        clients,
                        scenario,
                        n,
                        chatWorld,
                        httpStats,
                        noiseWorld,
                        clientViz,
                        trace,
                        crashCtx,
                        telemetry,
                    );
                    const dt = Date.now() - t0;
                    const offeredSlotsPerSec =
                        dt > 0 ? Math.round((ops * 1000) / dt) : 0;
                    trace?.append({
                        burst,
                        detail: {
                            concurrency: n,
                            dt_ms: dt,
                            kind: "burst_end",
                            offered_slots_per_sec: offeredSlotsPerSec,
                            ops,
                        },
                        event: "burst",
                        phase: crashCtx.phase,
                    });
                    burstWallMs.push(dt);
                    completedHttpOps += ops;
                    telemetry?.setBurstContext(burst, n);
                    telemetry?.setProgress(
                        completedHttpOps,
                        dt,
                        offeredSlotsPerSec,
                    );
                    dashboard?.setState({
                        completedHttpOps,
                        inFlight: 0,
                        lastBurstMs: dt,
                    });
                    if (stressQuietCli) {
                        writeStressCliWallSnapshot({
                            burstGapMs: sessionBurstGapMs,
                            clients: sessionClientCount,
                            concurrency: n,
                            host,
                            lastWallMs: dt,
                            loadPacing: sessionLoadPacing,
                            offeredSlotsPerSec,
                            opsCounted: completedHttpOps,
                            phase: crashCtx.phase,
                            scenario,
                            wallIndex: burst,
                            wallTotal: plannedRounds,
                        });
                    } else if (telemetry !== null || !useUi) {
                        process.stderr.write(
                            `[stress] wall ${String(burst)}/${String(plannedRounds)}  ${String(dt)}ms wall  ops=${String(ops)}  conc=${String(n)}  offered≈${String(offeredSlotsPerSec)} slots/s\n`,
                        );
                    }
                    if (
                        maxWallMs !== null &&
                        Date.now() - floodWallStart >= maxWallMs
                    ) {
                        if (!stressQuietCli) {
                            process.stderr.write(
                                `[stress] wall cap SPIRE_STRESS_MAX_WALL_SEC=${maxWallSecRaw}s reached — stopping flood.\n`,
                            );
                        } else {
                            process.stderr.write(
                                `[stress] wall cap ${maxWallSecRaw}s wall time — stopping flood.\n`,
                            );
                        }
                        break floodFinite;
                    }
                    if (applyQueuedRestart()) {
                        await Promise.all(clients.map((c) => c.close()));
                        sessionRestart = true;
                        if (!stressQuietCli) {
                            process.stderr.write(
                                "[stress] web: restarting with new parameters after flood wall.\n",
                            );
                        }
                        break floodFinite;
                    }
                    if (
                        sessionLoadPacing === "paced" &&
                        sessionBurstGapMs > 0 &&
                        r < plannedRounds - 1 &&
                        !stressRunShouldStop()
                    ) {
                        await sleepMs(sessionBurstGapMs);
                    }
                }
            }

            if (!sessionRestart) {
                await Promise.all(clients.map((c) => c.close()));
            }

            lastHttpStats = httpStats;
            lastBurstWallMs = [...burstWallMs];
            lastBurst = burst;
            lastCompletedHttpOps = completedHttpOps;
            lastSessionClientCount = sessionClientCount;

            if (stressRunShouldStop()) {
                break sessionLoop;
            }
            if (sessionRestart) {
                continue sessionLoop;
            }
            break sessionLoop;
        }

        lastBurstWallMs.sort((a, b) => a - b);
        const p50 =
            lastBurstWallMs.length > 0
                ? (lastBurstWallMs[
                      Math.floor((lastBurstWallMs.length - 1) / 2)
                  ] ?? 0)
                : 0;
        const p95 =
            lastBurstWallMs.length > 0
                ? (lastBurstWallMs[Math.floor(lastBurstWallMs.length * 0.95)] ??
                  lastBurstWallMs.at(-1) ??
                  0)
                : 0;
        const totalWallMs = lastBurstWallMs.reduce((a, b) => a + b, 0);

        const summary: StressRunSummary = {
            burstCount: lastBurst,
            clientCount: lastSessionClientCount,
            concurrencySnapshot: initialConcurrency,
            host,
            httpRequestsCompleted: lastCompletedHttpOps,
            httpResponsesByStatus: { ...lastHttpStats.byStatus },
            httpResponsesOk: lastHttpStats.ok,
            httpResponsesOther: lastHttpStats.other,
            lastConcurrency: knobsRef.knobs.concurrency,
            roundMedianMs: p50,
            roundP95Ms: p95,
            scenario,
            shutDownReason: runFlags.interrupted ? "interrupt" : "completed",
            totalWallMs,
        };

        crashCtx.phase = "done";
        dashboard?.setState({ phase: "done" });
        if (dashboard !== null) {
            dashboard.renderFinalSummary(summary);
        } else {
            writeStressRunSummary(summary, { quiet: stressQuietCli });
        }

        if (httpFailureTotal(lastHttpStats) > 0) {
            process.exitCode = 1;
        }

        traceEndedReason = runFlags.interrupted ? "interrupt" : "completed";
        Object.assign(traceSummary, {
            burstCount: summary.burstCount,
            clientCount: summary.clientCount,
            host: summary.host,
            httpFailures: httpFailureTotal(lastHttpStats),
            scenario: summary.scenario,
            totalWallMs: summary.totalWallMs,
            traceRunId: trace?.getRunId() ?? null,
        });
    } catch (err: unknown) {
        if (isLikelySpireDown(err) || isWrappedSpireUnreachable(err)) {
            traceEndedReason = "spire_unreachable";
            const shown =
                err instanceof Error && isWrappedSpireUnreachable(err)
                    ? err.message
                    : wrapSpireUnreachable(host, err).message;
            Object.assign(traceSummary, {
                error: shown,
                kind: "spire_unreachable",
                traceRunId: trace?.getRunId() ?? null,
            });
            trace?.append({
                burst: crashCtx.currentBurst,
                detail: { message: shown },
                event: "spire_unreachable",
                phase: crashCtx.phase,
            });
            process.stderr.write(`\n${shown}\n`);
            process.exitCode = 2;
            return;
        }
        traceEndedReason = "thrown";
        Object.assign(traceSummary, {
            error: err instanceof Error ? err.message : String(err),
            traceRunId: trace?.getRunId() ?? null,
        });
        trace?.append({
            burst: crashCtx.currentBurst,
            detail: {
                message: err instanceof Error ? err.message : String(err),
            },
            event: "sync_throw",
            phase: crashCtx.phase,
        });
        throw err;
    } finally {
        process.off("SIGINT", onSignal);
        process.off("SIGTERM", onSignal);
        detachStdin();
        if (webHandle !== null) {
            try {
                await webHandle.close();
            } catch {
                /* ignore */
            }
            webHandle = null;
        }
        trace?.finalizeRun({
            endedReason: traceEndedReason,
            summary: traceSummary,
        });
        trace?.close();
        uninstallCrashDump();
    }
}

void main().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(msg + "\n");
    process.exit(1);
});
