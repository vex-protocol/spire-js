/**
 * top-style full-screen TUI for the Spire stress harness (no extra deps).
 */
import type { StressClientViz } from "./stress-client-viz.ts";
import type { StressKnobs } from "./stress-knobs.ts";

import { existsSync } from "node:fs";
import { cpus, freemem, loadavg, totalmem } from "node:os";
import { monitorEventLoopDelay, performance } from "node:perf_hooks";

import axios from "axios";
import Database from "better-sqlite3";

import {
    formatHttpExpectLine,
    type HttpExpectStats,
} from "./stress-http-stats.ts";
import {
    type StressRunSummary,
    writeStressRunSummary,
} from "./stress-summary.ts";

const ALT_SCREEN_ON = "\x1b[?1049h";
const ALT_SCREEN_OFF = "\x1b[?1049l";
const CLEAR = "\x1b[2J\x1b[H";
const HIDE_CURSOR = "\x1b[?25l";
const SHOW_CURSOR = "\x1b[?25h";

const BOX = {
    h: "─",
    tl: "┌",
    tr: "┐",
    bl: "└",
    br: "┘",
    v: "│",
    lj: "├",
    rj: "┤",
} as const;

function isRecord(x: unknown): x is Record<string, unknown> {
    return typeof x === "object" && x !== null;
}

function readStatusPayload(raw: unknown): {
    checkDurationMs?: number;
    dbHealthy?: boolean;
    metrics?: { requestsTotal?: number };
} {
    if (!isRecord(raw)) {
        return {};
    }
    const metricsRaw = raw["metrics"];
    let metrics: { requestsTotal?: number } | undefined;
    if (isRecord(metricsRaw)) {
        const rt = metricsRaw["requestsTotal"];
        if (typeof rt === "number") {
            metrics = { requestsTotal: rt };
        }
    }
    const chk = raw["checkDurationMs"];
    const db = raw["dbHealthy"];
    const out: {
        checkDurationMs?: number;
        dbHealthy?: boolean;
        metrics?: { requestsTotal?: number };
    } = {};
    if (typeof chk === "number") {
        out.checkDurationMs = chk;
    }
    if (typeof db === "boolean") {
        out.dbHealthy = db;
    }
    if (metrics !== undefined) {
        out.metrics = metrics;
    }
    return out;
}

function readProcessSnapshot(raw: unknown): {
    hostOs?: { freemem: number; loadavg: number[]; totalmem: number };
    memory?: { heapUsed?: number; rss?: number };
    pid?: number;
    resourceUsage?: {
        fsRead?: number;
        fsWrite?: number;
        systemMicros?: number;
        userMicros?: number;
    };
    uptimeSeconds?: number;
    websocketClients?: number;
} | null {
    if (!isRecord(raw)) {
        return null;
    }
    const out: {
        hostOs?: { freemem: number; loadavg: number[]; totalmem: number };
        memory?: { heapUsed?: number; rss?: number };
        pid?: number;
        resourceUsage?: {
            fsRead?: number;
            fsWrite?: number;
            systemMicros?: number;
            userMicros?: number;
        };
        uptimeSeconds?: number;
        websocketClients?: number;
    } = {};
    const pid = raw["pid"];
    if (typeof pid === "number") {
        out.pid = pid;
    }
    const up = raw["uptimeSeconds"];
    if (typeof up === "number") {
        out.uptimeSeconds = up;
    }
    const ws = raw["websocketClients"];
    if (typeof ws === "number") {
        out.websocketClients = ws;
    }
    const memRaw = raw["memory"];
    if (isRecord(memRaw)) {
        const rss = memRaw["rss"];
        const heapUsed = memRaw["heapUsed"];
        const mem: { heapUsed?: number; rss?: number } = {};
        if (typeof rss === "number") {
            mem.rss = rss;
        }
        if (typeof heapUsed === "number") {
            mem.heapUsed = heapUsed;
        }
        if (mem.rss !== undefined || mem.heapUsed !== undefined) {
            out.memory = mem;
        }
    }
    const ruRaw = raw["resourceUsage"];
    if (isRecord(ruRaw)) {
        const ru: NonNullable<(typeof out)["resourceUsage"]> = {};
        const fr = ruRaw["fsRead"];
        const fw = ruRaw["fsWrite"];
        const um = ruRaw["userMicros"];
        const sm = ruRaw["systemMicros"];
        if (typeof fr === "number") {
            ru.fsRead = fr;
        }
        if (typeof fw === "number") {
            ru.fsWrite = fw;
        }
        if (typeof um === "number") {
            ru.userMicros = um;
        }
        if (typeof sm === "number") {
            ru.systemMicros = sm;
        }
        if (Object.keys(ru).length > 0) {
            out.resourceUsage = ru;
        }
    }
    const hoRaw = raw["hostOs"];
    if (isRecord(hoRaw)) {
        const fm = hoRaw["freemem"];
        const tm = hoRaw["totalmem"];
        const la = hoRaw["loadavg"];
        if (
            typeof fm === "number" &&
            typeof tm === "number" &&
            Array.isArray(la)
        ) {
            const laNums: number[] = [];
            for (const x of la) {
                if (typeof x !== "number") {
                    laNums.length = 0;
                    break;
                }
                laNums.push(x);
            }
            if (laNums.length === 3) {
                out.hostOs = { freemem: fm, loadavg: laNums, totalmem: tm };
            }
        }
    }
    return out;
}

export interface StressDashboardConfig {
    readonly clientCount: number;
    readonly clientViz: StressClientViz[] | null;
    readonly concurrencySnapshot: number;
    readonly forever: boolean;
    readonly host: string;
    readonly httpStats: HttpExpectStats | null;
    readonly knobs: StressKnobs | null;
    readonly plannedRounds: number;
    readonly scenario: string;
    readonly statusBaseUrl: string;
    /** Read-only poll of harness trace SQLite (same file stress may write). */
    readonly traceLogPath: string | null;
}

export interface StressDashboardState {
    completedHttpOps: number;
    currentBurst: number;
    inFlight: number;
    lastBurstMs: number;
    phase: "bootstrap" | "flood" | "done";
}

function termWidth(): number {
    const c = process.stdout.columns;
    if (typeof c === "number" && c >= 56) {
        return Math.min(132, c);
    }
    return 100;
}

/** Full-width top bar (top-style title line). */
function topBar(w: number, title: string): string {
    const t = ` ${title} `;
    const inner = w - 2;
    if (t.length >= inner) {
        return BOX.tl + t.slice(0, inner).padEnd(inner, BOX.h) + BOX.tr + "\n";
    }
    const pad = inner - t.length;
    const left = Math.floor(pad / 2);
    const right = pad - left;
    return (
        BOX.tl + BOX.h.repeat(left) + t + BOX.h.repeat(right) + BOX.tr + "\n"
    );
}

function sep(w: number): string {
    return BOX.lj + BOX.h.repeat(w - 2) + BOX.rj + "\n";
}

function row(w: number, text: string): string {
    const inner = w - 4;
    let s = text;
    if (s.length > inner) {
        s = `${s.slice(0, Math.max(0, inner - 1))}…`;
    }
    return `${BOX.v} ${s.padEnd(inner)} ${BOX.v}\n`;
}

function fmtBytes(n: number): string {
    if (n < 1024) return `${String(n)} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

function readSqliteMonitor(raw: unknown): string {
    if (!isRecord(raw)) {
        return "bad json";
    }
    if (raw["ok"] !== true) {
        return "unavailable";
    }
    const sq = raw["sqlite"];
    if (!isRecord(sq)) {
        return "no sqlite block";
    }
    const abs = sq["absPath"];
    const jm = sq["journalMode"];
    const pc = sq["pageCount"];
    const ps = sq["pageSize"];
    const fb = sq["fileBytes"];
    let wal = "?";
    let main = "?";
    if (isRecord(fb)) {
        const w = fb["wal"];
        const m = fb["main"];
        if (typeof w === "number") {
            wal = fmtBytes(w);
        }
        if (typeof m === "number") {
            main = fmtBytes(m);
        }
    }
    const absS = typeof abs === "string" ? abs.slice(-36) : "?";
    return `db ${absS}  ${String(jm)}  main ${main}  wal ${wal}  pages ${String(pc)}×${String(ps)}`;
}

function fmtMs(n: number): string {
    if (!Number.isFinite(n) || n < 0) return "—";
    if (n < 0.05) return "<0.1ms";
    if (n < 1) return `${n.toFixed(2)}ms`;
    return `${n.toFixed(1)}ms`;
}

function padL(s: string, w: number): string {
    return s.length >= w ? s.slice(0, w) : s.padStart(w);
}

function padR(s: string, w: number): string {
    return s.length >= w ? s.slice(0, w) : s.padEnd(w);
}

interface SpireProcSample {
    readonly fsRead: number;
    readonly fsWrite: number;
    readonly systemMicros: number;
    readonly t: number;
    readonly userMicros: number;
}

export class StressDashboard {
    private readonly elHistogram = monitorEventLoopDelay({ resolution: 20 });
    private readonly cfg: StressDashboardConfig;
    private interval: ReturnType<typeof setInterval> | null = null;
    private intervalMs = 400;
    private lastCpu = process.cpuUsage();
    private lastElu = performance.eventLoopUtilization();
    private lastRequestsTotal: null | number = null;
    private lastSpireProc: SpireProcSample | null = null;
    private pulseInFlight = false;
    private serverProcessLine = "";
    private serverPulseLine = "";
    private serverSpireLine = "";
    private serverSqliteLine = "";
    private traceHarnessLine = "";
    /** Read-only trace DB; eslint struggles with better-sqlite3 default export types. */
    // eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents
    private traceRo: Database | null = null;
    private state: StressDashboardState = {
        completedHttpOps: 0,
        currentBurst: 0,
        inFlight: 0,
        lastBurstMs: 0,
        phase: "bootstrap",
    };
    private useAltScreen = false;

    public constructor(cfg: StressDashboardConfig) {
        this.cfg = cfg;
    }

    public start(): void {
        this.intervalMs = Math.max(
            100,
            Number(process.env["SPIRE_STRESS_UI_INTERVAL_MS"] ?? "400"),
        );
        this.lastElu = performance.eventLoopUtilization();
        this.lastCpu = process.cpuUsage();
        this.elHistogram.enable();
        this.ensureTraceRo();
        if (process.stdout.isTTY) {
            this.useAltScreen = true;
            process.stdout.write(ALT_SCREEN_ON + HIDE_CURSOR);
        }
        this.interval = setInterval(() => {
            this.render();
        }, this.intervalMs);
    }

    public setState(patch: Partial<StressDashboardState>): void {
        this.state = { ...this.state, ...patch };
    }

    public stop(): void {
        if (this.interval !== null) {
            clearInterval(this.interval);
            this.interval = null;
        }
        if (this.traceRo !== null) {
            try {
                // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access -- better-sqlite3
                this.traceRo.close();
            } catch {
                /* ignore */
            }
            this.traceRo = null;
        }
        this.elHistogram.disable();
        if (process.stdout.isTTY) {
            if (this.useAltScreen) {
                process.stdout.write(ALT_SCREEN_OFF);
                this.useAltScreen = false;
            }
            process.stdout.write(SHOW_CURSOR);
        }
    }

    public renderFinalSummary(summary: StressRunSummary): void {
        this.stop();
        process.stdout.write(CLEAR);
        writeStressRunSummary(summary);
    }

    private ensureTraceRo(): void {
        if (this.traceRo !== null) {
            return;
        }
        const tp = this.cfg.traceLogPath;
        if (tp === null || tp.length === 0 || !existsSync(tp)) {
            return;
        }
        try {
            this.traceRo = new Database(tp, { readonly: true, timeout: 500 });
        } catch {
            this.traceRo = null;
        }
    }

    private refreshTraceHarness(): void {
        this.ensureTraceRo();
        if (this.traceRo === null) {
            this.traceHarnessLine = "";
            return;
        }
        /* eslint-disable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access -- better-sqlite3 */
        try {
            const cRow: unknown = this.traceRo
                .prepare("SELECT COUNT(*) AS c FROM harness_events")
                .get();
            let count = 0;
            if (isRecord(cRow)) {
                const c = cRow["c"];
                if (typeof c === "number") {
                    count = c;
                } else if (typeof c === "bigint") {
                    count = Number(c);
                }
            }
            const last: unknown = this.traceRo
                .prepare(
                    "SELECT seq, event, phase, burst FROM harness_events ORDER BY seq DESC LIMIT 1",
                )
                .get();
            let tail = "";
            if (isRecord(last)) {
                tail = `last #${String(last["seq"])} ${String(last["phase"])}/${String(last["event"])} b${String(last["burst"])}`;
            }
            this.traceHarnessLine = `events ${String(count)}  ${tail}`;
        } catch {
            this.traceHarnessLine = "trace DB busy/unreadable";
        }
        /* eslint-enable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access */
    }

    private scheduleServerPulse(): void {
        if (this.pulseInFlight) {
            return;
        }
        this.pulseInFlight = true;
        const base = this.cfg.statusBaseUrl.replace(/\/$/, "");
        const statusUrl = `${base}/status`;
        const processUrl = `${base}/status/process`;
        const sqliteUrl = `${base}/status/sqlite`;

        void Promise.all([
            axios.get(statusUrl, { timeout: 1200, validateStatus: () => true }),
            axios.get(processUrl, {
                timeout: 1200,
                validateStatus: () => true,
            }),
            axios.get(sqliteUrl, { timeout: 1200, validateStatus: () => true }),
        ])
            .then(([statusRes, procRes, sqliteRes]) => {
                if (statusRes.status !== 200) {
                    this.serverPulseLine = `HTTP ${String(statusRes.status)}`;
                } else {
                    const data = readStatusPayload(statusRes.data);
                    const chk = data.checkDurationMs ?? 0;
                    const ok = data.dbHealthy === true ? "ok" : "?";
                    let line = `health db=${ok} chk=${String(chk)}ms`;
                    const total = data.metrics?.requestsTotal;
                    if (typeof total === "number") {
                        if (this.lastRequestsTotal !== null) {
                            line += `  req Δ${String(total - this.lastRequestsTotal)}/tick`;
                        }
                        this.lastRequestsTotal = total;
                    }
                    this.serverPulseLine = line;
                }

                if (procRes.status === 404) {
                    this.serverProcessLine =
                        "dev snapshot off — set DEV_API_KEY on Spire (same as stress)";
                    this.serverSpireLine = this.serverProcessLine;
                } else if (procRes.status !== 200) {
                    this.serverProcessLine = `process HTTP ${String(procRes.status)}`;
                    this.serverSpireLine = this.serverProcessLine;
                } else {
                    const snap = readProcessSnapshot(procRes.data);
                    if (snap === null) {
                        this.serverProcessLine = "bad json";
                        this.serverSpireLine = this.serverProcessLine;
                    } else {
                        const rss = snap.memory?.rss;
                        const heap = snap.memory?.heapUsed;
                        const ru = snap.resourceUsage;
                        const now = Date.now();
                        let cpuApprox = "—";
                        let fsRd = "—";
                        let fsWr = "—";
                        if (
                            ru !== undefined &&
                            typeof ru.userMicros === "number" &&
                            typeof ru.systemMicros === "number" &&
                            typeof ru.fsRead === "number" &&
                            typeof ru.fsWrite === "number"
                        ) {
                            const prev = this.lastSpireProc;
                            if (prev !== null) {
                                const dt = (now - prev.t) / 1000;
                                if (dt > 0.05) {
                                    const du =
                                        (ru.userMicros - prev.userMicros) /
                                        1_000_000;
                                    const ds =
                                        (ru.systemMicros - prev.systemMicros) /
                                        1_000_000;
                                    cpuApprox = `${(((du + ds) / dt) * 100).toFixed(0)}%`;
                                    fsRd = `${String(Math.round((ru.fsRead - prev.fsRead) / dt))}/s`;
                                    fsWr = `${String(Math.round((ru.fsWrite - prev.fsWrite) / dt))}/s`;
                                }
                            }
                            this.lastSpireProc = {
                                fsRead: ru.fsRead,
                                fsWrite: ru.fsWrite,
                                systemMicros: ru.systemMicros,
                                t: now,
                                userMicros: ru.userMicros,
                            };
                        }
                        const ho = snap.hostOs;
                        let hostBit = "";
                        if (ho !== undefined) {
                            const freePct = Math.round(
                                (100 * ho.freemem) / ho.totalmem,
                            );
                            const la0 = ho.loadavg[0]?.toFixed(2) ?? "?";
                            hostBit = `  host load[0]=${la0}  freeRAM=${String(freePct)}%`;
                        }
                        const rssS =
                            typeof rss === "number" ? fmtBytes(rss) : "?";
                        const heapS =
                            typeof heap === "number" ? fmtBytes(heap) : "?";
                        const pid =
                            typeof snap.pid === "number"
                                ? String(snap.pid)
                                : "?";
                        const ws =
                            typeof snap.websocketClients === "number"
                                ? String(snap.websocketClients)
                                : "?";
                        this.serverSpireLine =
                            `pid ${pid}  rss ${rssS}  heap ${heapS}  ws ${ws}` +
                            `  Spire-CPU~${cpuApprox}  fs rd ${fsRd} wr ${fsWr}${hostBit}`;
                        this.serverProcessLine = this.serverSpireLine;
                    }
                }

                if (sqliteRes.status === 404) {
                    this.serverSqliteLine =
                        "sqlite dev off (same DEV_API_KEY gate)";
                } else if (sqliteRes.status !== 200) {
                    this.serverSqliteLine = `sqlite HTTP ${String(sqliteRes.status)}`;
                } else {
                    this.serverSqliteLine = readSqliteMonitor(sqliteRes.data);
                }
            })
            .catch(() => {
                this.serverPulseLine = "unreachable";
                this.serverProcessLine = "unreachable";
                this.serverSpireLine = "unreachable";
                this.serverSqliteLine = "unreachable";
            })
            .finally(() => {
                this.pulseInFlight = false;
            });
    }

    private render(): void {
        this.scheduleServerPulse();
        this.refreshTraceHarness();

        const mu = process.memoryUsage();
        const ru = process.resourceUsage();
        const cpu = process.cpuUsage(this.lastCpu);
        this.lastCpu = process.cpuUsage();

        const eluDelta = performance.eventLoopUtilization(this.lastElu);
        this.lastElu = performance.eventLoopUtilization();

        const meanDelayNs = this.elHistogram.mean;
        const maxDelayNs = this.elHistogram.max;
        this.elHistogram.reset();

        const { completedHttpOps, currentBurst, inFlight, lastBurstMs, phase } =
            this.state;
        const {
            clientCount,
            clientViz,
            concurrencySnapshot,
            forever,
            host,
            httpStats,
            knobs,
            plannedRounds,
            scenario,
        } = this.cfg;

        const liveConcurrency = knobs?.concurrency ?? concurrencySnapshot;

        const rps =
            lastBurstMs > 0
                ? ((clientCount * liveConcurrency) / lastBurstMs) * 1000
                : 0;

        const cpuUserMs = cpu.user / 1000;
        const cpuSysMs = cpu.system / 1000;

        const burstCol = forever
            ? String(currentBurst)
            : `${String(currentBurst)}/${String(plannedRounds)}`;
        const la = loadavg();
        const laStr = `${la[0]?.toFixed(2) ?? "?"} ${la[1]?.toFixed(2) ?? "?"} ${la[2]?.toFixed(2) ?? "?"}`;
        const localFreePct = Math.round((100 * freemem()) / totalmem());
        const now = new Date().toLocaleTimeString(undefined, { hour12: false });
        const uiVerbose = process.env["SPIRE_STRESS_UI_VERBOSE"] === "1";

        const w = termWidth();
        const pulse =
            this.serverPulseLine.length > 0 ? this.serverPulseLine : "…";
        const procSnap =
            this.serverSpireLine.length > 0 ? this.serverSpireLine : "…";
        const sqlLine =
            this.serverSqliteLine.length > 0 ? this.serverSqliteLine : "…";
        const traceLine =
            this.traceHarnessLine.length > 0
                ? this.traceHarnessLine
                : this.cfg.traceLogPath === null
                  ? "(no trace DB path)"
                  : "…";

        const metricHeader =
            `${padR("burst", 10)}${padR("inflight", 9)}${padR("last_ms", 9)}` +
            `${padR("ops", 12)}${padR("rps~", 8)}${padR("load 1/5/15", 18)}${padR("cpus", 5)}`;
        const metricRow =
            `${padL(String(currentBurst), 10)}${padL(String(inFlight), 9)}` +
            padL(lastBurstMs > 0 ? String(lastBurstMs) : "—", 9) +
            `${padL(String(completedHttpOps), 12)}${padL(rps.toFixed(0), 8)}` +
            `${padL(laStr, 18)}${padL(String(cpus().length), 5)}`;

        let fsLine = "";
        if (typeof ru.fsRead === "number" && typeof ru.fsWrite === "number") {
            fsLine = row(
                w,
                `FS (this process)  read_ops ${String(ru.fsRead)}  write_ops ${String(ru.fsWrite)}`,
            );
        }

        const out: string[] = [];
        out.push(CLEAR);
        out.push(topBar(w, `spire-stress  ${now}`));
        out.push(
            row(
                w,
                `SPIRE-STRESS   host ${host}   scenario ${scenario}   clients ${String(clientCount)}`,
            ),
        );
        out.push(
            row(
                w,
                `phase ${phase}   burst ${burstCol}   conc ${String(liveConcurrency)} (start ${String(concurrencySnapshot)})   ui ${String(this.intervalMs)}ms`,
            ),
        );
        out.push(sep(w));
        out.push(row(w, `  ${metricHeader}`));
        out.push(row(w, `  ${metricRow}`));
        out.push(sep(w));
        out.push(row(w, "THIS MACHINE (stress host)"));
        out.push(
            row(
                w,
                `  loadavg 1/5/15  ${laStr}   cpus ${String(cpus().length)}   freeRAM ${String(localFreePct)}% (this Node OS view)`,
            ),
        );
        out.push(sep(w));
        out.push(row(w, "SPIRE SERVER (dev key on /status/*)"));
        out.push(row(w, `  /status          ${pulse}`));
        out.push(row(w, `  /status/process  ${procSnap}`));
        out.push(row(w, `  /status/sqlite   ${sqlLine}`));
        out.push(sep(w));
        out.push(row(w, "STRESS HARNESS trace DB (read-only, local file)"));
        out.push(
            row(w, `  ${this.cfg.traceLogPath ?? "(unset)"}  →  ${traceLine}`),
        );
        out.push(sep(w));
        if (httpStats !== null) {
            const inner = w - 4;
            out.push(
                row(
                    w,
                    `libvex HTTP (cumulative)  ${formatHttpExpectLine(httpStats, inner - 26)}`,
                ),
            );
        }
        if (clientViz !== null && clientViz.length > 0) {
            out.push(sep(w));
            out.push(row(w, "CLIENTS  #  last op (crypto RNG)  ok  total ops"));
            for (let i = 0; i < clientCount; i++) {
                const v = clientViz[i];
                const active =
                    v !== undefined && v.inFlight.length > 0
                        ? v.inFlight
                        : (v?.lastOp ?? "—");
                const op = active.slice(0, 18);
                const okMark = v?.lastOk === false ? "✗" : "✓";
                const oc = v !== undefined ? String(v.ops) : "0";
                out.push(
                    row(
                        w,
                        `  ${padR(`#${String(i)}`, 4)}${padR(op, 20)}  ${padR(okMark, 3)}${padL(oc, 6)}`,
                    ),
                );
            }
        }
        out.push(sep(w));
        out.push(
            row(
                w,
                `STRESS DRIVER (this process)  rss ${fmtBytes(mu.rss)}  heap ${fmtBytes(mu.heapUsed)}  cpuΔ usr ${cpuUserMs.toFixed(0)}ms sys ${cpuSysMs.toFixed(0)}ms`,
            ),
        );
        if (uiVerbose) {
            out.push(
                row(
                    w,
                    `  verbose  el% ${(eluDelta.utilization * 100).toFixed(0)}  elμ ${fmtMs(meanDelayNs / 1e6)}  elMx ${fmtMs(maxDelayNs / 1e6)}  ext ${fmtBytes(mu.external)}`,
                ),
            );
            if (fsLine.length > 0) {
                out.push(fsLine);
            }
        }
        out.push(sep(w));
        if (knobs !== null && forever) {
            out.push(
                row(
                    w,
                    "KEYS  + / =  up   -  down   0  reset   q  quit   Ctrl+C  quit",
                ),
            );
        } else {
            out.push(
                row(
                    w,
                    "KEYS  (live tuning only when run is forever)   SPIRE_STRESS_ROUNDS=N  finite",
                ),
            );
        }
        out.push(
            row(
                w,
                "NOTE  SPIRE_STRESS_PLAIN=1  no TUI.  SPIRE_STRESS_UI_VERBOSE=1  event-loop detail.  Deep I/O: sample/fs_usage on Spire PID.",
            ),
        );
        out.push(BOX.bl + BOX.h.repeat(w - 2) + BOX.br + "\n");

        if (process.stdout.isTTY) {
            process.stdout.write(out.join(""));
        }
    }
}
