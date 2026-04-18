/**
 * Append-only SQLite log of harness steps + fatal incidents (for post-mortems).
 *
 * SPIRE_STRESS_TRACE=0     — disable (no file).
 * SPIRE_STRESS_TRACE_DB=   — path to .sqlite file (default: ~/.spire-stress/traces.sqlite).
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";

import Database from "better-sqlite3";

const INSERT_RUN = `
INSERT INTO runs (run_id, started_at, host, scenario, client_count)
VALUES (@run_id, @started_at, @host, @scenario, @client_count)
`;

const FINISH_RUN = `
UPDATE runs SET finished_at = @finished_at, ended_reason = @ended_reason, summary_json = @summary_json
WHERE run_id = @run_id
`;

const INSERT_EVENT = `
INSERT INTO harness_events (run_id, seq, ts_ms, phase, burst, client_index, event, detail_json)
VALUES (@run_id, @seq, @ts_ms, @phase, @burst, @client_index, @event, @detail_json)
`;

const INSERT_INCIDENT = `
INSERT INTO incidents (run_id, ts_ms, kind, message, node_stack, harness_snapshot_json, recent_events_json)
VALUES (@run_id, @ts_ms, @kind, @message, @node_stack, @harness_snapshot_json, @recent_events_json)
`;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  host TEXT NOT NULL,
  scenario TEXT NOT NULL,
  client_count INTEGER NOT NULL,
  ended_reason TEXT,
  summary_json TEXT
);

CREATE TABLE IF NOT EXISTS harness_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  ts_ms INTEGER NOT NULL,
  phase TEXT NOT NULL,
  burst INTEGER NOT NULL,
  client_index INTEGER,
  event TEXT NOT NULL,
  detail_json TEXT,
  UNIQUE (run_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_harness_run_seq ON harness_events (run_id, seq);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  ts_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  node_stack TEXT,
  harness_snapshot_json TEXT,
  recent_events_json TEXT
);
`;

export interface StressTraceEventInput {
    readonly burst: number;
    readonly clientIndex?: number;
    readonly detail?: Record<string, unknown>;
    readonly event: string;
    readonly phase: string;
}

function defaultDbPath(): string {
    const base = join(homedir(), ".spire-stress");
    try {
        mkdirSync(base, { recursive: true });
    } catch {
        return join(tmpdir(), "spire-stress-traces.sqlite");
    }
    return join(base, "traces.sqlite");
}

export class StressTraceDb {
    private readonly db: Database.Database;
    private readonly runId: string;
    private seq = 0;
    private closed = false;
    private runStarted = false;

    public constructor(dbPath: string) {
        mkdirSync(dirname(dbPath), { recursive: true });
        this.db = new Database(dbPath);
        this.db.pragma("journal_mode = WAL");
        this.db.pragma("synchronous = NORMAL");
        this.db.exec(SCHEMA);
        this.runId = randomUUID();
    }

    public static tryOpenFromEnv(): StressTraceDb | null {
        const off = process.env["SPIRE_STRESS_TRACE"]?.trim() === "0";
        if (off) {
            return null;
        }
        const raw = process.env["SPIRE_STRESS_TRACE_DB"]?.trim();
        const path =
            raw !== undefined && raw.length > 0 ? raw : defaultDbPath();
        try {
            return new StressTraceDb(path);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            process.stderr.write(
                `[spire-stress] SPIRE_STRESS_TRACE_DB open failed (${path}): ${msg}\n`,
            );
            return null;
        }
    }

    public getRunId(): string {
        return this.runId;
    }

    public getDbPathForDisplay(): string {
        return this.db.name;
    }

    public beginRun(input: {
        readonly clientCount: number;
        readonly host: string;
        readonly scenario: string;
    }): void {
        this.runStarted = true;
        const startedAt = new Date().toISOString();
        this.db.prepare(INSERT_RUN).run({
            client_count: input.clientCount,
            host: input.host,
            run_id: this.runId,
            scenario: input.scenario,
            started_at: startedAt,
        });
    }

    public append(input: StressTraceEventInput): void {
        this.seq += 1;
        const tsMs = Date.now();
        const detailJson =
            input.detail !== undefined ? JSON.stringify(input.detail) : null;
        this.db.prepare(INSERT_EVENT).run({
            burst: input.burst,
            client_index: input.clientIndex ?? null,
            detail_json: detailJson,
            event: input.event,
            phase: input.phase,
            run_id: this.runId,
            seq: this.seq,
            ts_ms: tsMs,
        });
    }

    public finalizeRun(input: {
        readonly endedReason: string;
        readonly summary: Record<string, unknown>;
    }): void {
        if (this.closed || !this.runStarted) {
            return;
        }
        this.db.prepare(FINISH_RUN).run({
            ended_reason: input.endedReason,
            finished_at: new Date().toISOString(),
            run_id: this.runId,
            summary_json: JSON.stringify(input.summary),
        });
    }

    public recentEvents(limit: number): Record<string, unknown>[] {
        const raw = this.db
            .prepare(
                `SELECT seq, ts_ms, phase, burst, client_index, event, detail_json
         FROM harness_events WHERE run_id = ? ORDER BY seq DESC LIMIT ?`,
            )
            .all(this.runId, limit);
        if (!Array.isArray(raw)) {
            return [];
        }
        const out: Record<string, unknown>[] = [];
        for (const item of raw) {
            if (typeof item !== "object" || item === null) {
                continue;
            }
            const seq: unknown = Reflect.get(item, "seq");
            const tsMs: unknown = Reflect.get(item, "ts_ms");
            const phase: unknown = Reflect.get(item, "phase");
            const burst: unknown = Reflect.get(item, "burst");
            const clientIndex: unknown = Reflect.get(item, "client_index");
            const event: unknown = Reflect.get(item, "event");
            const detailJson: unknown = Reflect.get(item, "detail_json");
            if (
                typeof seq !== "number" ||
                typeof tsMs !== "number" ||
                typeof phase !== "string" ||
                typeof burst !== "number" ||
                typeof event !== "string"
            ) {
                continue;
            }
            let detail: unknown = null;
            if (typeof detailJson === "string") {
                try {
                    detail = JSON.parse(detailJson) as unknown;
                } catch {
                    detail = null;
                }
            }
            out.push({
                burst,
                client_index:
                    clientIndex === null || typeof clientIndex === "number"
                        ? clientIndex
                        : null,
                detail,
                event,
                phase,
                seq,
                ts_ms: tsMs,
            });
        }
        return out;
    }

    public captureFatal(input: {
        readonly harnessSnapshot: Record<string, unknown>;
        readonly kind: "uncaughtException" | "unhandledRejection";
        readonly reason: unknown;
    }): void {
        const err = input.reason;
        const message = err instanceof Error ? err.message : String(err);
        const nodeStack =
            err instanceof Error ? (err.stack ?? message) : message;
        const recent = this.recentEvents(120);
        this.db.prepare(INSERT_INCIDENT).run({
            harness_snapshot_json: JSON.stringify(input.harnessSnapshot),
            kind: input.kind,
            message,
            node_stack: nodeStack,
            recent_events_json: JSON.stringify(recent),
            run_id: this.runId,
            ts_ms: Date.now(),
        });
        const burstRaw = input.harnessSnapshot["burst"];
        const burstNum =
            typeof burstRaw === "number" && Number.isFinite(burstRaw)
                ? burstRaw
                : 0;
        const phaseRaw = input.harnessSnapshot["phase"];
        const phaseStr = typeof phaseRaw === "string" ? phaseRaw : "?";
        this.append({
            burst: burstNum,
            detail: {
                incident: true,
                kind: input.kind,
                message,
            },
            event: "fatal",
            phase: phaseStr,
        });
    }

    public close(): void {
        if (this.closed) {
            return;
        }
        this.closed = true;
        this.db.close();
    }
}

export type StressTraceSink = StressTraceDb | null;

/** Path to an existing stress trace DB for read-only UI polling (may be null). */
export function probeStressTraceDbPathForReading(): string | null {
    if (process.env["SPIRE_STRESS_TRACE"]?.trim() === "0") {
        return null;
    }
    const raw = process.env["SPIRE_STRESS_TRACE_DB"]?.trim();
    if (raw !== undefined && raw.length > 0) {
        return existsSync(raw) ? raw : null;
    }
    const p = join(homedir(), ".spire-stress", "traces.sqlite");
    return existsSync(p) ? p : null;
}
