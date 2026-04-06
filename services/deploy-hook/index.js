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
    const bearer = extractBearer(
        Array.isArray(auth) ? auth[0] : auth ?? "",
    );
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
            env: process.env,
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
            stdout = out.stdout;
            stderr = out.stderr;
        } catch (e) {
            if (e && typeof e === "object") {
                if ("stdout" in e && typeof e.stdout === "string") {
                    stdout = e.stdout;
                }
                if ("stderr" in e && typeof e.stderr === "string") {
                    stderr = e.stderr;
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

    await step("git", ["fetch", "origin"]);
    await step("git", ["checkout", gitRef]);
    await step("git", ["pull", "--ff-only", "origin", gitRef]);
    await step("npm", ["install"]);
    await step("pm2", ["restart", pm2App]);

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
                sendJson(res, 200, { ok: true });
                return;
            }

            if (req.method !== "POST" || pathname !== "/deploy") {
                sendJson(res, 404, { ok: false, error: "Not found." });
                return;
            }

            await drainRequest(req);

            const provided = getProvidedSecret(req);
            if (!secretMatches(provided, secret)) {
                sendJson(res, 401, { ok: false, error: "Unauthorized." });
                return;
            }

            if (busy) {
                sendJson(res, 409, {
                    ok: false,
                    error: "Deploy already in progress.",
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
                sendJson(res, 500, {
                    ok: false,
                    error: message,
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
            sendJson(res, 200, { ok: true, steps, stepLogs });
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            sendJson(res, 500, { ok: false, error: message });
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
