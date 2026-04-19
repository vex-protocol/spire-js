/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import Database from "better-sqlite3";
import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import { createServer } from "node:http";
import path from "node:path";

const DEV_API_KEY_HEADER = "x-dev-api-key";

/**
 * Same contract as Spire `devApiKeySkipsRateLimits`: when `DEV_API_KEY` is set,
 * the header must match (constant-time). When unset, returns true (local dev).
 */
function devApiKeyAuthorized(req, configuredKey) {
    const configured = configuredKey?.trim() ?? "";
    if (configured.length === 0) {
        return true;
    }
    const presented = req.headers[DEV_API_KEY_HEADER];
    if (!presented || presented.length !== configured.length) {
        return false;
    }
    try {
        return timingSafeEqual(
            Buffer.from(presented, "utf8"),
            Buffer.from(configured, "utf8"),
        );
    } catch {
        return false;
    }
}

const DEFAULT_URL = "https://api.vex.wtf/status";
const DEFAULT_INTERVAL_MS = 60_000;
const DEFAULT_DB_PATH = "./monitoring/status-history.sqlite";
const DEFAULT_API_PORT = 6767;
const DEFAULT_API_HOST = "0.0.0.0";

function parseArgs(argv) {
    const config = {
        url: process.env.STATUS_URL || DEFAULT_URL,
        intervalMs: Number(
            process.env.STATUS_INTERVAL_MS || DEFAULT_INTERVAL_MS,
        ),
        dbPath: process.env.STATUS_DB_PATH || DEFAULT_DB_PATH,
        apiPort: Number(process.env.STATUS_API_PORT || DEFAULT_API_PORT),
        apiHost: process.env.STATUS_API_HOST || DEFAULT_API_HOST,
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
            continue;
        }
        if (arg === "--port" && argv[i + 1]) {
            config.apiPort = Number(argv[i + 1]);
            i += 1;
            continue;
        }
        if (arg === "--host" && argv[i + 1]) {
            config.apiHost = argv[i + 1];
            i += 1;
        }
    }

    if (!Number.isFinite(config.intervalMs) || config.intervalMs < 1_000) {
        throw new Error("Interval must be >= 1000ms.");
    }
    if (
        !Number.isFinite(config.apiPort) ||
        config.apiPort < 1 ||
        config.apiPort > 65535
    ) {
        throw new Error("Port must be between 1 and 65535.");
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

async function collectOnce(targetUrl, devApiKey) {
    const started = Date.now();
    const sampledAt = new Date().toISOString();

    try {
        const headers = {
            Accept: "application/json",
        };
        const key = devApiKey?.trim() ?? "";
        if (key.length > 0) {
            headers[DEV_API_KEY_HEADER] = key;
        }
        const response = await fetch(targetUrl, {
            headers,
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
            activeWebsocketClients: null,
            dbReady: payload?.dbReady ?? payload?.dependencies?.dbReady ?? null,
            dbHealthy:
                payload?.dbHealthy ?? payload?.dependencies?.dbHealthy ?? null,
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
        dbHealthy: sample.dbHealthy === null ? null : sample.dbHealthy ? 1 : 0,
    });
}

function formatLog(sample) {
    const status = sample.ok ? "UP" : "DOWN";
    const code = sample.httpStatus ?? "ERR";
    const latency = `${sample.requestLatencyMs}ms`;
    const reqs =
        sample.requestsTotal === null ? "-" : String(sample.requestsTotal);
    const err = sample.errorText ? ` error="${sample.errorText}"` : "";
    return `[${sample.sampledAt}] ${status} code=${code} latency=${latency} reqs=${reqs}${err}`;
}

function toPublicRow(row) {
    if (!row) {
        return null;
    }
    return {
        id: row.id,
        sampledAt: row.sampled_at,
        targetUrl: row.target_url,
        ok: Boolean(row.ok),
        httpStatus: row.http_status,
        requestLatencyMs: row.request_latency_ms,
        serviceUptimeSeconds: row.service_uptime_seconds,
        serviceVersion: row.service_version,
        serviceCommitSha: row.service_commit_sha,
        statusCheckDurationMs: row.status_check_duration_ms,
        withinLatencyBudget:
            row.within_latency_budget === null
                ? null
                : Boolean(row.within_latency_budget),
        requestsTotal: row.requests_total,
        dbReady: row.db_ready === null ? null : Boolean(row.db_ready),
        dbHealthy: row.db_healthy === null ? null : Boolean(row.db_healthy),
        errorText: row.error_text,
    };
}

function getLatestSample(db) {
    const row = db
        .prepare(
            `
        SELECT *
        FROM status_samples
        ORDER BY id DESC
        LIMIT 1
    `,
        )
        .get();
    return toPublicRow(row);
}

function getSummary(db, hours) {
    const windowStart = new Date(
        Date.now() - hours * 60 * 60 * 1000,
    ).toISOString();
    const row = db
        .prepare(
            `
        SELECT
            COUNT(*) AS total_samples,
            SUM(CASE WHEN ok = 1 THEN 1 ELSE 0 END) AS up_samples,
            AVG(request_latency_ms) AS avg_latency_ms,
            MAX(request_latency_ms) AS max_latency_ms
        FROM status_samples
        WHERE sampled_at >= ?
    `,
        )
        .get(windowStart);

    const totalSamples = Number(row?.total_samples || 0);
    const upSamples = Number(row?.up_samples || 0);
    return {
        windowHours: hours,
        totalSamples,
        upSamples,
        downSamples: Math.max(0, totalSamples - upSamples),
        uptimePercent:
            totalSamples === 0 ? 0 : (upSamples / totalSamples) * 100,
        averageLatencyMs:
            row?.avg_latency_ms === null ? null : Number(row.avg_latency_ms),
        maxLatencyMs:
            row?.max_latency_ms === null ? null : Number(row.max_latency_ms),
        latest: getLatestSample(db),
    };
}

function roundOneDecimal(value) {
    return Math.round(value * 10) / 10;
}

function percentile(values, p) {
    if (values.length === 0) {
        return null;
    }
    const sorted = [...values].sort((a, b) => a - b);
    const rank = Math.ceil((p / 100) * sorted.length) - 1;
    const idx = Math.min(sorted.length - 1, Math.max(0, rank));
    return sorted[idx];
}

function getTimeseriesBuckets(db, windowHours, bucketMinutes) {
    const windowStartMs = Date.now() - windowHours * 60 * 60 * 1000;
    const bucketMs = bucketMinutes * 60 * 1000;
    const alignedWindowStartMs =
        Math.floor(windowStartMs / bucketMs) * bucketMs;
    const nowMs = Date.now();

    const rows = db
        .prepare(
            `
        SELECT
            sampled_at,
            ok,
            request_latency_ms,
            requests_total
        FROM status_samples
        WHERE sampled_at >= ?
        ORDER BY sampled_at ASC
    `,
        )
        .all(new Date(alignedWindowStartMs).toISOString());

    const bucketMap = new Map();

    for (
        let bucketStartMs = alignedWindowStartMs;
        bucketStartMs <= nowMs;
        bucketStartMs += bucketMs
    ) {
        bucketMap.set(bucketStartMs, {
            bucketStartMs,
            bucketEndMs: bucketStartMs + bucketMs - 1,
            sampleCount: 0,
            upCount: 0,
            downCount: 0,
            latencies: [],
            requestsTotalMin: null,
            requestsTotalMax: null,
            samples: [],
        });
    }

    for (const row of rows) {
        const sampledMs = Date.parse(row.sampled_at);
        if (!Number.isFinite(sampledMs)) {
            continue;
        }
        const bucketStartMs = Math.floor(sampledMs / bucketMs) * bucketMs;
        const bucket = bucketMap.get(bucketStartMs);
        if (!bucket) {
            continue;
        }
        bucket.sampleCount += 1;
        const sampleOk = Boolean(row.ok);
        if (sampleOk) {
            bucket.upCount += 1;
        } else {
            bucket.downCount += 1;
        }
        bucket.samples.push({
            sampledAt: row.sampled_at,
            ok: sampleOk,
        });
        if (typeof row.request_latency_ms === "number") {
            bucket.latencies.push(row.request_latency_ms);
        }
        if (row.requests_total !== null && row.requests_total !== undefined) {
            const rt = Number(row.requests_total);
            if (Number.isFinite(rt)) {
                bucket.requestsTotalMin =
                    bucket.requestsTotalMin === null
                        ? rt
                        : Math.min(bucket.requestsTotalMin, rt);
                bucket.requestsTotalMax =
                    bucket.requestsTotalMax === null
                        ? rt
                        : Math.max(bucket.requestsTotalMax, rt);
            }
        }
    }

    const blocks = Array.from(bucketMap.values()).map((bucket) => {
        const uptimePercent =
            bucket.sampleCount === 0
                ? 0
                : (bucket.upCount / bucket.sampleCount) * 100;
        const avgLatencyMs =
            bucket.latencies.length === 0
                ? null
                : roundOneDecimal(
                      bucket.latencies.reduce((sum, n) => sum + n, 0) /
                          bucket.latencies.length,
                  );
        const p95LatencyMs = percentile(bucket.latencies, 95);
        const maxLatencyMs =
            bucket.latencies.length === 0
                ? null
                : Math.max(...bucket.latencies);

        let status = "no_data";
        if (bucket.sampleCount > 0) {
            status = bucket.downCount === 0 ? "up" : "down";
        }

        let serviceRequestsDelta = null;
        if (
            bucket.requestsTotalMin !== null &&
            bucket.requestsTotalMax !== null &&
            bucket.requestsTotalMax >= bucket.requestsTotalMin
        ) {
            serviceRequestsDelta =
                bucket.requestsTotalMax - bucket.requestsTotalMin;
        }

        return {
            bucketStart: new Date(bucket.bucketStartMs).toISOString(),
            bucketEnd: new Date(bucket.bucketEndMs).toISOString(),
            sampleCount: bucket.sampleCount,
            upCount: bucket.upCount,
            downCount: bucket.downCount,
            requests: {
                total: bucket.sampleCount,
                online: bucket.upCount,
                offline: bucket.downCount,
            },
            serviceRequestsDelta,
            uptimePercent: roundOneDecimal(uptimePercent),
            avgLatencyMs,
            p95LatencyMs,
            maxLatencyMs,
            status,
            samples: bucket.samples,
            sampleTimestamps: bucket.samples.map((sample) => sample.sampledAt),
        };
    });

    return {
        windowHours,
        bucketMinutes,
        blocks,
    };
}

function sendJson(res, statusCode, payload) {
    res.statusCode = statusCode;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
        "Access-Control-Allow-Headers",
        `Content-Type, Authorization, ${DEV_API_KEY_HEADER}`,
    );
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.end(JSON.stringify(payload));
}

function startApiServer(db, host, port, devApiKeyConfigured) {
    const server = createServer((req, res) => {
        try {
            // Apply CORS headers for every response path, including errors.
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader(
                "Access-Control-Allow-Headers",
                `Content-Type, Authorization, ${DEV_API_KEY_HEADER}`,
            );
            res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");

            if (req.method === "OPTIONS") {
                res.statusCode = 204;
                res.end();
                return;
            }

            const baseUrl = `http://${req.headers.host || "localhost"}`;
            const url = new URL(req.url || "/", baseUrl);

            if (req.method !== "GET") {
                sendJson(res, 405, { error: "Method not allowed." });
                return;
            }

            if (url.pathname === "/healthz") {
                sendJson(res, 200, { ok: true });
                return;
            }

            if (url.pathname === "/latest" || url.pathname === "/api/latest") {
                if (!devApiKeyAuthorized(req, devApiKeyConfigured)) {
                    sendJson(res, 404, { error: "Not found." });
                    return;
                }
                sendJson(res, 200, { data: getLatestSample(db) });
                return;
            }

            if (
                url.pathname === "/summary" ||
                url.pathname === "/api/summary"
            ) {
                if (!devApiKeyAuthorized(req, devApiKeyConfigured)) {
                    sendJson(res, 404, { error: "Not found." });
                    return;
                }
                const hours = Number(url.searchParams.get("hours") || "24");
                if (!Number.isFinite(hours) || hours <= 0) {
                    sendJson(res, 400, { error: "hours must be > 0" });
                    return;
                }
                sendJson(res, 200, { data: getSummary(db, hours) });
                return;
            }

            if (
                url.pathname === "/timeseries" ||
                url.pathname === "/api/timeseries"
            ) {
                if (!devApiKeyAuthorized(req, devApiKeyConfigured)) {
                    sendJson(res, 404, { error: "Not found." });
                    return;
                }
                const windowHours = Number(
                    url.searchParams.get("windowHours") ||
                        url.searchParams.get("hours") ||
                        "24",
                );
                const bucketMinutes = Number(
                    url.searchParams.get("bucketMinutes") || "1440",
                );

                if (!Number.isFinite(windowHours) || windowHours <= 0) {
                    sendJson(res, 400, {
                        error: "windowHours must be > 0",
                    });
                    return;
                }
                if (
                    !Number.isFinite(bucketMinutes) ||
                    bucketMinutes < 1 ||
                    bucketMinutes > 10_080
                ) {
                    sendJson(res, 400, {
                        error: "bucketMinutes must be between 1 and 10080",
                    });
                    return;
                }
                sendJson(res, 200, {
                    data: getTimeseriesBuckets(db, windowHours, bucketMinutes),
                });
                return;
            }

            sendJson(res, 404, { error: "Not found." });
        } catch (err) {
            sendJson(res, 500, {
                error: err instanceof Error ? err.message : String(err),
            });
        }
    });

    server.listen(port, host);
    return server;
}

async function main() {
    const config = parseArgs(process.argv.slice(2));
    const devApiKeyForSpire = process.env.DEV_API_KEY?.trim() ?? "";
    const db = initializeDatabase(config.dbPath);
    const apiServer = startApiServer(
        db,
        config.apiHost,
        config.apiPort,
        devApiKeyForSpire,
    );

    console.log(`Monitoring ${config.url}`);
    console.log(`Interval: ${config.intervalMs}ms`);
    console.log(`Database: ${config.dbPath}`);
    console.log(`API: http://${config.apiHost}:${config.apiPort}`);

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
            apiServer.close();
            db.close();
            process.exit(130);
        }
    };

    process.on("SIGINT", requestShutdown);
    process.on("SIGTERM", requestShutdown);

    try {
        while (!shutdownRequested) {
            const sample = await collectOnce(config.url, devApiKeyForSpire);
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
        await new Promise((resolve) => {
            apiServer.close(() => resolve());
        });
        db.close();
    }

    console.log("Status monitor stopped.");
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
