import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";

const DEFAULT_URL = "https://api.vex.wtf/status";
const DEFAULT_INTERVAL_MS = 10_000;
const DEFAULT_DB_PATH = "./monitoring/status-history.sqlite";

function parseArgs(argv) {
    const config = {
        url: process.env.STATUS_URL || DEFAULT_URL,
        intervalMs: Number(process.env.STATUS_INTERVAL_MS || DEFAULT_INTERVAL_MS),
        dbPath: process.env.STATUS_DB_PATH || DEFAULT_DB_PATH,
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--url" && argv[i + 1]) {
            config.url = argv[i + 1];
            i += 1;
            continue;
        }
        if (arg === "--interval" && argv[i + 1]) {
            config.intervalMs = Number(argv[i + 1]);
            i += 1;
            continue;
        }
        if (arg === "--db" && argv[i + 1]) {
            config.dbPath = argv[i + 1];
            i += 1;
        }
    }

    if (!Number.isFinite(config.intervalMs) || config.intervalMs < 1_000) {
        throw new Error("Interval must be >= 1000ms.");
    }

    return config;
}

function initializeDatabase(dbPath) {
    const directory = path.dirname(dbPath);
    fs.mkdirSync(directory, { recursive: true });

    const db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = NORMAL");

    db.exec(`
        CREATE TABLE IF NOT EXISTS status_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sampled_at TEXT NOT NULL,
            target_url TEXT NOT NULL,
            ok INTEGER NOT NULL,
            http_status INTEGER,
            request_latency_ms INTEGER,
            service_uptime_seconds INTEGER,
            service_version TEXT,
            service_commit_sha TEXT,
            status_check_duration_ms INTEGER,
            within_latency_budget INTEGER,
            requests_total INTEGER,
            active_websocket_clients INTEGER,
            db_ready INTEGER,
            db_healthy INTEGER,
            error_text TEXT,
            raw_json TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_status_samples_sampled_at
            ON status_samples(sampled_at);
    `);

    return db;
}

async function collectOnce(targetUrl) {
    const started = Date.now();
    const sampledAt = new Date().toISOString();

    try {
        const response = await fetch(targetUrl, {
            headers: {
                Accept: "application/json",
            },
        });

        const requestLatencyMs = Date.now() - started;
        let payload = null;
        try {
            payload = await response.json();
        } catch {
            payload = null;
        }

        return {
            sampledAt,
            targetUrl,
            ok: response.ok && Boolean(payload?.ok),
            httpStatus: response.status,
            requestLatencyMs,
            serviceUptimeSeconds: payload?.uptimeSeconds ?? null,
            serviceVersion: payload?.version ?? null,
            serviceCommitSha: payload?.commitSha ?? null,
            statusCheckDurationMs: payload?.checkDurationMs ?? null,
            withinLatencyBudget:
                payload?.withinLatencyBudget === undefined
                    ? null
                    : payload.withinLatencyBudget,
            requestsTotal: payload?.metrics?.requestsTotal ?? null,
            activeWebsocketClients:
                payload?.metrics?.activeWebsocketClients ?? null,
            dbReady: payload?.dependencies?.dbReady ?? null,
            dbHealthy: payload?.dependencies?.dbHealthy ?? null,
            errorText: null,
            rawJson: payload ? JSON.stringify(payload) : null,
        };
    } catch (err) {
        return {
            sampledAt,
            targetUrl,
            ok: false,
            httpStatus: null,
            requestLatencyMs: Date.now() - started,
            serviceUptimeSeconds: null,
            serviceVersion: null,
            serviceCommitSha: null,
            statusCheckDurationMs: null,
            withinLatencyBudget: null,
            requestsTotal: null,
            activeWebsocketClients: null,
            dbReady: null,
            dbHealthy: null,
            errorText: err instanceof Error ? err.message : String(err),
            rawJson: null,
        };
    }
}

function insertSample(db, sample) {
    const stmt = db.prepare(`
        INSERT INTO status_samples (
            sampled_at,
            target_url,
            ok,
            http_status,
            request_latency_ms,
            service_uptime_seconds,
            service_version,
            service_commit_sha,
            status_check_duration_ms,
            within_latency_budget,
            requests_total,
            active_websocket_clients,
            db_ready,
            db_healthy,
            error_text,
            raw_json
        ) VALUES (
            @sampledAt,
            @targetUrl,
            @ok,
            @httpStatus,
            @requestLatencyMs,
            @serviceUptimeSeconds,
            @serviceVersion,
            @serviceCommitSha,
            @statusCheckDurationMs,
            @withinLatencyBudget,
            @requestsTotal,
            @activeWebsocketClients,
            @dbReady,
            @dbHealthy,
            @errorText,
            @rawJson
        )
    `);

    stmt.run({
        ...sample,
        ok: sample.ok ? 1 : 0,
        withinLatencyBudget:
            sample.withinLatencyBudget === null
                ? null
                : sample.withinLatencyBudget
                  ? 1
                  : 0,
        dbReady: sample.dbReady === null ? null : sample.dbReady ? 1 : 0,
        dbHealthy:
            sample.dbHealthy === null ? null : sample.dbHealthy ? 1 : 0,
    });
}

function formatLog(sample) {
    const status = sample.ok ? "UP" : "DOWN";
    const code = sample.httpStatus ?? "ERR";
    const latency = `${sample.requestLatencyMs}ms`;
    const ws =
        sample.activeWebsocketClients === null
            ? "-"
            : String(sample.activeWebsocketClients);
    const reqs = sample.requestsTotal === null ? "-" : String(sample.requestsTotal);
    const err = sample.errorText ? ` error="${sample.errorText}"` : "";
    return `[${sample.sampledAt}] ${status} code=${code} latency=${latency} ws=${ws} reqs=${reqs}${err}`;
}

async function main() {
    const config = parseArgs(process.argv.slice(2));
    const db = initializeDatabase(config.dbPath);

    console.log(`Monitoring ${config.url}`);
    console.log(`Interval: ${config.intervalMs}ms`);
    console.log(`Database: ${config.dbPath}`);

    let shutdownRequested = false;
    let forceExitRequested = false;
    let sleepTimer = null;

    const requestShutdown = () => {
        if (!shutdownRequested) {
            shutdownRequested = true;
            console.log("Shutdown requested, finishing current cycle...");
            if (sleepTimer) {
                clearTimeout(sleepTimer);
                sleepTimer = null;
            }
            return;
        }

        if (!forceExitRequested) {
            forceExitRequested = true;
            console.log("Force exiting.");
            db.close();
            process.exit(130);
        }
    };

    process.on("SIGINT", requestShutdown);
    process.on("SIGTERM", requestShutdown);

    try {
        while (!shutdownRequested) {
            const sample = await collectOnce(config.url);
            insertSample(db, sample);
            console.log(formatLog(sample));

            if (shutdownRequested) {
                break;
            }

            await new Promise((resolve) => {
                sleepTimer = setTimeout(() => {
                    sleepTimer = null;
                    resolve();
                }, config.intervalMs);
            });
        }
    } finally {
        if (sleepTimer) {
            clearTimeout(sleepTimer);
            sleepTimer = null;
        }
        process.off("SIGINT", requestShutdown);
        process.off("SIGTERM", requestShutdown);
        db.close();
    }

    console.log("Status monitor stopped.");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
