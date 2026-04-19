/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import path from "node:path";
import { loadEnv } from "../../src/utils/loadEnv.ts";

loadEnv();

const DEFAULT_PORT = 6868;
const DEFAULT_HOST = "0.0.0.0";
const DEFAULT_GIT_REF = "master";
const DEFAULT_PM2_APP = "spire";
const DEFAULT_LOG_CHARS_PER_STREAM = 65_536;

/** Strip ANSI escape sequences (colors, cursor moves) for plain logs. */
function stripAnsi(text) {
    if (!text) {
        return text;
    }
    return text
        .replace(/\u001b\[[\d;?]*[\dA-Za-z]/g, "")
        .replace(/\u001b][\d;]*[^\u0007]*\u0007/g, "");
}

function childProcessEnv() {
    if (process.env.DEPLOY_HOOK_KEEP_COLORS === "1") {
        return process.env;
    }
    return {
        ...process.env,
        NO_COLOR: "1",
        FORCE_COLOR: "0",
        CI: process.env.CI || "1",
    };
}

function envString(name, fallback) {
    const v = process.env[name];
    return v === undefined || v === "" ? fallback : v;
}

function envInt(name, fallback) {
    const n = Number(process.env[name]);
    return Number.isFinite(n) ? n : fallback;
}

function extractBearer(authHeader) {
    if (!authHeader || typeof authHeader !== "string") {
        return null;
    }
    const m = /^Bearer\s+(\S+)$/i.exec(authHeader.trim());
    return m ? m[1] : null;
}

function secretMatches(provided, expected) {
    if (typeof provided !== "string" || typeof expected !== "string") {
        return false;
    }
    const a = Buffer.from(provided, "utf8");
    const b = Buffer.from(expected, "utf8");
    if (a.length !== b.length) {
        return false;
    }
    return timingSafeEqual(a, b);
}

function getProvidedSecret(req) {
    const headerSecret = req.headers["x-deploy-secret"];
    if (typeof headerSecret === "string" && headerSecret.length > 0) {
        return headerSecret;
    }
    const auth = req.headers.authorization;
    const bearer = extractBearer(Array.isArray(auth) ? auth[0] : (auth ?? ""));
    if (bearer) {
        return bearer;
    }
    return null;
}

function clipStream(text, maxChars) {
    if (maxChars <= 0 || text.length <= maxChars) {
        return { text, truncated: false };
    }
    const omitted = text.length - maxChars;
    return {
        text: `… (${omitted} chars omitted from start)\n${text.slice(-maxChars)}`,
        truncated: true,
    };
}

function run(cmd, args, cwd) {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, {
            cwd,
            env: childProcessEnv(),
            stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d) => {
            stdout += d;
        });
        child.stderr.on("data", (d) => {
            stderr += d;
        });
        child.on("error", reject);
        child.on("close", (code) => {
            if (code === 0) {
                resolve({ stdout, stderr });
            } else {
                const tail = (stderr || stdout).slice(-4000);
                const err = new Error(
                    `${cmd} ${args.join(" ")} exited with code ${code}: ${tail}`,
                );
                err.stdout = stdout;
                err.stderr = stderr;
                err.exitCode = code;
                reject(err);
            }
        });
    });
}

async function runDeploy({ repoRoot, gitRef, pm2App }) {
    const stepLogs = [];
    const maxStream = envInt(
        "DEPLOY_HOOK_LOG_CHARS_PER_STREAM",
        DEFAULT_LOG_CHARS_PER_STREAM,
    );

    function appendResponseLog(command, stdout, stderr) {
        const co = clipStream(stdout, maxStream);
        const ce = clipStream(stderr, maxStream);
        stepLogs.push({
            command,
            stdout: co.text,
            stderr: ce.text,
            truncated: co.truncated || ce.truncated,
        });
    }

    async function step(cmd, args) {
        const command = `${cmd} ${args.join(" ")}`;
        console.log(`[deploy-hook] --- ${command} ---`);
        let stdout = "";
        let stderr = "";
        try {
            const out = await run(cmd, args, repoRoot);
            stdout = stripAnsi(out.stdout);
            stderr = stripAnsi(out.stderr);
        } catch (e) {
            if (e && typeof e === "object") {
                if ("stdout" in e && typeof e.stdout === "string") {
                    stdout = stripAnsi(e.stdout);
                }
                if ("stderr" in e && typeof e.stderr === "string") {
                    stderr = stripAnsi(e.stderr);
                }
            }
            if (stdout) {
                process.stdout.write(
                    stdout.endsWith("\n") ? stdout : `${stdout}\n`,
                );
            }
            if (stderr) {
                process.stderr.write(
                    stderr.endsWith("\n") ? stderr : `${stderr}\n`,
                );
            }
            appendResponseLog(command, stdout, stderr);
            if (e instanceof Error) {
                e.stepLogs = stepLogs;
                throw e;
            }
            const wrapped = new Error(String(e));
            wrapped.stepLogs = stepLogs;
            throw wrapped;
        }
        if (stdout) {
            process.stdout.write(
                stdout.endsWith("\n") ? stdout : `${stdout}\n`,
            );
        }
        if (stderr) {
            process.stderr.write(
                stderr.endsWith("\n") ? stderr : `${stderr}\n`,
            );
        }
        appendResponseLog(command, stdout, stderr);
    }

    function formatPm2SummaryFromJlist(rawJson, name) {
        let list;
        try {
            list = JSON.parse(rawJson.trim());
        } catch {
            return "pm2 jlist: invalid JSON\n";
        }
        if (!Array.isArray(list)) {
            return "pm2 jlist: unexpected shape\n";
        }
        const app = list.find((p) => p && p.name === name);
        if (!app) {
            return `pm2 jlist: no process named "${name}"\n`;
        }
        const memKb = app.monit?.memory;
        const mem =
            typeof memKb === "number"
                ? `${(memKb / 1024 / 1024).toFixed(1)} MiB`
                : "?";
        const cpu =
            typeof app.monit?.cpu === "number" ? `${app.monit.cpu}%` : "?";
        const status = app.pm2_env?.status ?? "?";
        const pid = app.pid ?? "?";
        const restarts = app.pm2_env?.restart_time ?? "?";
        const startedMs = app.pm2_env?.pm_uptime;
        const uptime =
            typeof startedMs === "number"
                ? `${Math.max(0, Math.floor((Date.now() - startedMs) / 1000))}s`
                : "?";
        return `${name}: status=${status} pid=${pid} cpu=${cpu} mem=${mem} uptime=${uptime} restarts=${restarts}\n`;
    }

    /**
     * pm2 restart prints a Unicode table; omit it from logs and record a plain line from jlist.
     */
    async function stepPm2Restart(name) {
        const command = `pm2 restart ${name}`;
        console.log(`[deploy-hook] --- ${command} ---`);
        let restartOut = "";
        let restartErr = "";
        try {
            const out = await run("pm2", ["restart", name], repoRoot);
            restartOut = stripAnsi(out.stdout);
            restartErr = stripAnsi(out.stderr);
        } catch (e) {
            if (e && typeof e === "object") {
                if ("stdout" in e && typeof e.stdout === "string") {
                    restartOut = stripAnsi(e.stdout);
                }
                if ("stderr" in e && typeof e.stderr === "string") {
                    restartErr = stripAnsi(e.stderr);
                }
            }
            const tail = (restartErr || restartOut).trim();
            if (tail) {
                process.stdout.write(`${tail}\n`);
            }
            appendResponseLog(command, restartOut, restartErr);
            if (e instanceof Error) {
                e.stepLogs = stepLogs;
                throw e;
            }
            const wrapped = new Error(String(e));
            wrapped.stepLogs = stepLogs;
            throw wrapped;
        }

        let summary = "";
        try {
            const { stdout: jraw } = await run("pm2", ["jlist"], repoRoot);
            summary = formatPm2SummaryFromJlist(jraw, name);
        } catch (e2) {
            summary = `pm2 jlist failed: ${e2 instanceof Error ? e2.message : e2}\n`;
        }

        const plainStdout = summary;
        const plainStderr =
            restartErr.trim() !== "" ? `${restartErr.trim()}\n` : "";

        process.stdout.write(plainStdout);
        if (plainStderr) {
            process.stderr.write(plainStderr);
        }

        appendResponseLog(command, plainStdout, plainStderr);
    }

    await step("git", ["fetch", "origin"]);
    await step("git", ["checkout", gitRef]);
    await step("git", ["pull", "--ff-only", "origin", gitRef]);
    await step("npm", ["install"]);
    await stepPm2Restart(pm2App);

    const steps = stepLogs.map((s) => s.command);
    return { steps, stepLogs };
}

function sendJson(res, status, body) {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify(body));
}

function drainRequest(req) {
    return new Promise((resolve) => {
        req.resume();
        req.on("end", resolve);
        req.on("error", resolve);
    });
}

function readConfig() {
    const secret = process.env.DEPLOY_HOOK_SECRET;
    const repoRoot = path.resolve(
        process.env.DEPLOY_REPO_ROOT || process.cwd(),
    );
    const port = envInt("DEPLOY_HOOK_PORT", DEFAULT_PORT);
    const host = envString("DEPLOY_HOOK_HOST", DEFAULT_HOST);
    const gitRef = envString("DEPLOY_GIT_REF", DEFAULT_GIT_REF);
    const pm2App = envString("DEPLOY_PM2_APP", DEFAULT_PM2_APP);
    return { secret, repoRoot, port, host, gitRef, pm2App };
}

async function main() {
    const { secret, repoRoot, port, host, gitRef, pm2App } = readConfig();

    if (!secret) {
        console.error("DEPLOY_HOOK_SECRET is required.");
        process.exit(1);
    }

    let busy = false;

    const server = createServer(async (req, res) => {
        try {
            const base = `http://${req.headers.host || "localhost"}`;
            const url = new URL(req.url || "/", base);
            const pathname = url.pathname.replace(/\/+$/, "") || "/";

            if (req.method === "GET" && pathname === "/healthz") {
                sendJson(res, 200, { ok: true, outcome: "success" });
                return;
            }

            if (req.method !== "POST" || pathname !== "/deploy") {
                sendJson(res, 404, {
                    ok: false,
                    outcome: "failure",
                    error: "Not found.",
                    errorCode: "not_found",
                });
                return;
            }

            await drainRequest(req);

            const provided = getProvidedSecret(req);
            if (!secretMatches(provided, secret)) {
                sendJson(res, 401, {
                    ok: false,
                    outcome: "failure",
                    error: "Unauthorized.",
                    errorCode: "unauthorized",
                });
                return;
            }

            if (busy) {
                sendJson(res, 409, {
                    ok: false,
                    outcome: "failure",
                    error: "Deploy already in progress.",
                    errorCode: "conflict",
                });
                return;
            }

            busy = true;
            let steps;
            let stepLogs;
            try {
                ({ steps, stepLogs } = await runDeploy({
                    repoRoot,
                    gitRef,
                    pm2App,
                }));
            } catch (err) {
                const message =
                    err instanceof Error ? err.message : String(err);
                console.error("[deploy-hook] deploy failed:", message);
                const partialLogs =
                    err &&
                    typeof err === "object" &&
                    Array.isArray(err.stepLogs)
                        ? err.stepLogs
                        : undefined;
                sendJson(res, 422, {
                    ok: false,
                    outcome: "failure",
                    error: message,
                    errorCode: "deploy_failed",
                    ...(partialLogs !== undefined
                        ? { stepLogs: partialLogs }
                        : {}),
                });
                return;
            } finally {
                busy = false;
            }

            console.log(
                `[deploy-hook] completed deploy at ${repoRoot} (${steps.join(" -> ")})`,
            );
            sendJson(res, 200, {
                ok: true,
                outcome: "success",
                steps,
                stepLogs,
            });
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            sendJson(res, 500, {
                ok: false,
                outcome: "failure",
                error: message,
                errorCode: "internal_error",
            });
        }
    });

    server.listen(port, host, () => {
        console.log(
            `Deploy hook listening on http://${host}:${port} (repo: ${repoRoot}, ref: ${gitRef}, pm2: ${pm2App})`,
        );
    });
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
