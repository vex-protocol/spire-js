/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Dev-only dashboard for spire-stress: static UI + JSON snapshot + SSE updates.
 */
import type {
    StressRestartQueue,
    StressWebRestartRequest,
} from "./stress-restart-queue.ts";
import type { StressTelemetry } from "./stress-telemetry.ts";

import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

import { parseStressLoadPacing } from "./stress-load-pacing.ts";
import { slimStressUiSnapshotForWire } from "./stress-sse-snapshot.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Throttle SSE JSON writes — each `JSON.stringify(fullSnapshot)` can be MB+ under load. */
function createThrottledSseSender(res: {
    write(chunk: string): boolean;
}): (snap: ReturnType<StressTelemetry["getSnapshot"]>) => void {
    let lastSent = 0;
    let queued: ReturnType<StressTelemetry["getSnapshot"]> | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const minIntervalMs = 120;

    const flush = (): void => {
        timer = null;
        if (queued === null) {
            return;
        }
        const snap = queued;
        queued = null;
        lastSent = Date.now();
        const wire = slimStressUiSnapshotForWire(snap);
        res.write(`data: ${JSON.stringify(wire)}\n\n`);
    };

    return (snap: ReturnType<StressTelemetry["getSnapshot"]>) => {
        const now = Date.now();
        const elapsed = now - lastSent;
        if (lastSent === 0 || elapsed >= minIntervalMs) {
            if (timer !== null) {
                clearTimeout(timer);
                timer = null;
            }
            queued = null;
            lastSent = now;
            const wire = slimStressUiSnapshotForWire(snap);
            res.write(`data: ${JSON.stringify(wire)}\n\n`);
            return;
        }
        queued = snap;
        if (timer === null) {
            timer = setTimeout(flush, minIntervalMs - elapsed);
        }
    };
}

export interface StressWebServerHandle {
    readonly port: number;
    close(): Promise<void>;
}

function listenOnce(
    server: ReturnType<typeof createServer>,
    port: number,
): Promise<void> {
    return new Promise((resolve, reject) => {
        const onErr = (err: NodeJS.ErrnoException): void => {
            server.off("listening", onListening);
            reject(err);
        };
        const onListening = (): void => {
            server.off("error", onErr);
            resolve();
        };
        server.once("error", onErr);
        server.listen(port, "127.0.0.1", onListening);
    });
}

export interface StressWebServerOptions {
    readonly restartQueue: StressRestartQueue;
    readonly scenario: string;
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function clampInt(
    n: unknown,
    lo: number,
    hi: number,
    fallback: number,
): number {
    const v =
        typeof n === "number"
            ? n
            : typeof n === "string"
              ? Number(n)
              : Number.NaN;
    if (!Number.isFinite(v)) {
        return fallback;
    }
    return Math.max(lo, Math.min(hi, Math.floor(v)));
}

export async function startStressWebServer(
    telemetry: StressTelemetry,
    preferredPort: number,
    opts: StressWebServerOptions,
): Promise<StressWebServerHandle> {
    const app = express();
    const jsonParser = express.json({ limit: "8kb" });
    const htmlPath = join(__dirname, "web", "index.html");
    const html = readFileSync(htmlPath, "utf8");

    app.get("/", (_req, res) => {
        res.status(200).type("html").send(html);
    });

    app.get("/api/snapshot", (_req, res) => {
        res.setHeader("Cache-Control", "no-store");
        res.status(200).json(
            slimStressUiSnapshotForWire(telemetry.getSnapshot()),
        );
    });

    app.post("/api/restart-run", jsonParser, (req, res) => {
        const rawBody: unknown = req.body;
        if (!isJsonObject(rawBody)) {
            res.status(400).json({ error: "JSON body required", ok: false });
            return;
        }
        const body = rawBody;
        const clientCount = clampInt(body["clientCount"], 1, 500, 10);
        const concurrency = clampInt(body["concurrency"], 1, 5000, 25);
        const loadRaw =
            typeof body["loadPacing"] === "string"
                ? body["loadPacing"]
                : typeof body["loadMode"] === "string"
                  ? body["loadMode"]
                  : "";
        const loadPacing = parseStressLoadPacing(loadRaw);
        const burstGapMs =
            loadPacing === "paced"
                ? clampInt(body["burstGapMs"], 0, 300_000, 750)
                : 0;
        if (
            opts.scenario === "noise" &&
            (process.env["SPIRE_STRESS_USERNAME"]?.trim() ?? "").length > 0 &&
            clientCount !== 1
        ) {
            res.status(400).json({
                error: "SPIRE_STRESS_SCENARIO=noise with SPIRE_STRESS_USERNAME requires clientCount=1",
                ok: false,
            });
            return;
        }
        const reqBody: StressWebRestartRequest = {
            burstGapMs,
            clientCount,
            concurrency,
            loadPacing,
        };
        opts.restartQueue.schedule(reqBody);
        telemetry.setRestartPending(true);
        res.status(202).json({
            message:
                "Restart scheduled after the current flood wall completes.",
            ok: true,
        });
    });

    app.get("/api/stream", (req, res) => {
        res.status(200);
        res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        if (typeof res.flushHeaders === "function") {
            res.flushHeaders();
        }
        const send = createThrottledSseSender(res);
        const unsub = telemetry.subscribe(send);
        const ping = setInterval(() => {
            res.write(": ping\n\n");
        }, 25_000);
        req.on("close", () => {
            clearInterval(ping);
            unsub();
        });
    });

    const server = createServer(app);
    let boundPort = preferredPort;
    let listening = false;
    for (let attempt = 0; attempt < 40; attempt++) {
        try {
            await listenOnce(server, boundPort);
            listening = true;
            break;
        } catch (e: unknown) {
            let code: string | undefined;
            if (typeof e === "object" && e !== null && "code" in e) {
                const c = (e as { readonly code?: unknown }).code;
                if (typeof c === "string") {
                    code = c;
                }
            }
            await new Promise<void>((r) => {
                server.close(() => {
                    r();
                });
            });
            if (code !== "EADDRINUSE" || boundPort >= 65_535) {
                throw e;
            }
            boundPort += 1;
        }
    }
    if (!listening) {
        throw new Error("stress web: could not bind a free port");
    }

    return {
        close: () =>
            new Promise((resolve, reject) => {
                server.close((e) => {
                    if (e) {
                        reject(e);
                    } else {
                        resolve();
                    }
                });
            }),
        port: boundPort,
    };
}
