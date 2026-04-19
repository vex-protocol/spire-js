/**
 * Headless stress matrix (CI-style): run spire-stress for each (clients × concurrency) combo.
 * Each child exits after **N flood walls** (default 10), not a time budget — use `--seconds` only if you also want a wall-time cap.
 *
 * Requires DEV_API_KEY (same as Spire). Loads `.env` from the spire-js package root via dotenv, like `stress:web`.
 *
 * @example
 *   DEV_API_KEY=secret npm run stress:cli -- --walls 10 --clients 5,10 --conc 20,40
 *
 * @example Chat scenario, stop the matrix on first harness failure (exit 1):
 *   DEV_API_KEY=secret npm run stress:cli -- --scenario chat --stop-on-fail
 */

import type { StressUiFacetRow } from "./stress-telemetry.ts";

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { config } from "dotenv";

import {
    parseStressLoadPacing,
    type StressLoadPacing,
} from "./stress-load-pacing.ts";
import {
    formatStressFacetCiReport,
    mergeStressFacetRowLists,
    type StressFacetDumpV1,
} from "./stress-summary.ts";

function isRecord(x: unknown): x is Record<PropertyKey, unknown> {
    return typeof x === "object" && x !== null;
}

function isStressUiFacetRow(x: unknown): x is StressUiFacetRow {
    if (!isRecord(x)) {
        return false;
    }
    const r = x;
    const g = r["group"];
    const status = r["status"];
    return (
        typeof r["id"] === "string" &&
        typeof r["apiCall"] === "string" &&
        typeof r["description"] === "string" &&
        typeof r["fail"] === "number" &&
        typeof r["ok"] === "number" &&
        typeof r["protocolPath"] === "string" &&
        typeof r["title"] === "string" &&
        (g === "bootstrap" || g === "load" || g === "world") &&
        (status === "idle" ||
            status === "ok" ||
            status === "warn" ||
            status === "fail")
    );
}

function parseFacetDumpFile(raw: string): StressFacetDumpV1 | null {
    let data: unknown;
    try {
        data = JSON.parse(raw) as unknown;
    } catch {
        return null;
    }
    if (!isRecord(data)) {
        return null;
    }
    const o = data;
    if (o["v"] !== 1) {
        return null;
    }
    if (typeof o["host"] !== "string" || typeof o["scenario"] !== "string") {
        return null;
    }
    const facetsIn = o["facets"];
    if (!Array.isArray(facetsIn)) {
        return null;
    }
    const facets: StressUiFacetRow[] = [];
    for (const row of facetsIn) {
        if (!isStressUiFacetRow(row)) {
            return null;
        }
        facets.push(row);
    }
    return { v: 1, host: o["host"], scenario: o["scenario"], facets };
}

const SPIRE_JS_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const STRESS_ENTRY = join(
    SPIRE_JS_ROOT,
    "scripts",
    "stress",
    "spire-stress.ts",
);

function parseCommaNums(label: string, raw: string): number[] {
    const parts = raw
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    const out: number[] = [];
    for (const p of parts) {
        const n = Number(p);
        if (!Number.isFinite(n) || n < 1) {
            throw new Error(`${label}: expected positive integers, got "${p}"`);
        }
        out.push(Math.floor(n));
    }
    if (out.length === 0) {
        throw new Error(`${label}: need at least one value`);
    }
    return out;
}

function parseArgs(argv: string[]): {
    burstGapMs: string | undefined;
    clients: number[];
    conc: number[];
    help: boolean;
    host: string | undefined;
    loadPacing: StressLoadPacing;
    scenario: string;
    /** Optional `SPIRE_STRESS_MAX_WALL_SEC` ceiling (in addition to `--walls`). */
    seconds: number | undefined;
    stopOnFail: boolean;
    walls: number;
} {
    let clientsRaw = "10";
    let concRaw = "25";
    let seconds: number | undefined;
    let walls = 10;
    let scenario = "noise";
    let loadPacing: StressLoadPacing = "immediate";
    let burstGapMs: string | undefined;
    let host: string | undefined;
    let stopOnFail = false;
    let help = false;

    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === "--help" || a === "-h") {
            help = true;
            break;
        }
        const next = (): string => {
            const v = argv[i + 1];
            if (v === undefined || v.startsWith("--")) {
                throw new Error(`Missing value after ${String(a)}`);
            }
            i += 1;
            return v;
        };
        if (a === "--clients") {
            clientsRaw = next();
        } else if (a === "--conc" || a === "--concurrency") {
            concRaw = next();
        } else if (a === "--walls") {
            walls = Math.max(1, Math.floor(Number(next())));
            if (!Number.isFinite(walls)) {
                throw new Error("--walls must be a positive integer");
            }
        } else if (a === "--seconds") {
            const s = Math.max(1, Math.floor(Number(next())));
            if (!Number.isFinite(s)) {
                throw new Error("--seconds must be a number");
            }
            seconds = s;
        } else if (a === "--scenario") {
            scenario = next();
        } else if (a === "--load") {
            loadPacing = parseStressLoadPacing(next());
        } else if (a === "--burst-gap-ms") {
            burstGapMs = next();
        } else if (a === "--host") {
            host = next();
        } else if (a === "--stop-on-fail") {
            stopOnFail = true;
        } else {
            throw new Error(`Unknown argument: ${String(a)}`);
        }
    }

    return {
        burstGapMs,
        clients: parseCommaNums("--clients", clientsRaw),
        conc: parseCommaNums("--conc", concRaw),
        help,
        host,
        loadPacing,
        scenario,
        seconds,
        stopOnFail,
        walls,
    };
}

function printHelp(): void {
    process.stderr.write(
        [
            "stress:cli — headless clients × concurrency matrix (no web UI).",
            "",
            "Usage:",
            "  DEV_API_KEY=… npm run stress:cli -- [options]",
            "",
            "Options:",
            "  --walls <n>           flood walls per combo (default 10); sets SPIRE_STRESS_ROUNDS",
            "  --clients <n>[,n…]     client counts (default 10)",
            "  --conc <n>[,n…]       per-client concurrency values (default 25)",
            "  --seconds <n>         optional SPIRE_STRESS_MAX_WALL_SEC ceiling (wall time + paced gaps)",
            "  --scenario <name>     SPIRE_STRESS_SCENARIO (default noise)",
            "  --load immediate|paced  SPIRE_STRESS_LOAD_MODE (default immediate; legacy: continuous|burst)",
            "  --burst-gap-ms <n>    SPIRE_STRESS_BURST_GAP_MS when load=paced",
            "  --host <host:port>    SPIRE_STRESS_HOST",
            "  --stop-on-fail        stop the matrix early if a child exits with code 1 (harness saw HTTP failures)",
            "  -h, --help",
            "",
            "Child runs with SPIRE_STRESS_WEB=0 (quiet stderr). Per-wall logs: SPIRE_STRESS_VERBOSE=1 on the child.",
            "  Facet CI table: each child defers stdout; after the full matrix, one merged ✓/✗ table is printed (same as summing per-combo dumps). Direct spire-stress (not stress:cli) still prints its own table.",
            "  SPIRE_STRESS_FACET_REPORT=0 off, =1 on, =all include idle surfaces. SPIRE_STRESS_JSON=1 adds facets[] in JSON.",
            "",
        ].join("\n"),
    );
}

async function runChild(env: Record<string, string>): Promise<number> {
    return await new Promise((resolve, reject) => {
        const child = spawn(
            process.execPath,
            ["--experimental-strip-types", STRESS_ENTRY],
            {
                cwd: SPIRE_JS_ROOT,
                env: { ...process.env, ...env },
                stdio: ["ignore", "inherit", "inherit"],
            },
        );
        child.on("error", reject);
        child.on("close", (code, signal) => {
            if (signal) {
                resolve(1);
                return;
            }
            resolve(code ?? 1);
        });
    });
}

async function main(): Promise<void> {
    config();
    const argv = process.argv.slice(2);
    let opts;
    try {
        opts = parseArgs(argv);
    } catch (e) {
        process.stderr.write(
            (e instanceof Error ? e.message : String(e)) + "\n",
        );
        process.stderr.write("Try npm run stress:cli -- --help\n");
        process.exit(1);
    }
    if (opts.help) {
        printHelp();
        process.exit(0);
    }

    const dev = process.env["DEV_API_KEY"]?.trim() ?? "";
    if (dev.length === 0) {
        process.stderr.write("DEV_API_KEY is required in the environment.\n");
        process.exit(1);
    }

    const rows: string[] = [
        "combo\tclients\tconc\texit",
        "-----\t-------\t----\t----",
    ];

    let worst = 0;
    let combo = 0;
    const total = opts.clients.length * opts.conc.length;
    const facetDumpPaths: string[] = [];

    const cap =
        opts.seconds !== undefined
            ? `, cap ${String(opts.seconds)}s wall time`
            : "";
    process.stderr.write(
        `\nstress:cli — ${String(total)} combo(s), ${String(opts.walls)} wall(s)/combo${cap}, scenario=${opts.scenario}, pacing=${opts.loadPacing}\n\n`,
    );

    matrix: for (const c of opts.clients) {
        for (const n of opts.conc) {
            combo += 1;
            process.stderr.write(
                `--- [${String(combo)}/${String(total)}] clients=${String(c)} concurrency=${String(n)} ---\n`,
            );
            const dumpPath = join(
                tmpdir(),
                `spire-stress-facet-${String(combo)}-${randomUUID()}.json`,
            );
            facetDumpPaths.push(dumpPath);
            const env: Record<string, string> = {
                DEV_API_KEY: dev,
                SPIRE_STRESS_CLIENTS: String(c),
                SPIRE_STRESS_CONCURRENCY: String(n),
                SPIRE_STRESS_SCENARIO: opts.scenario,
                /** Finite run: exit after N walls (not time-based forever loop). */
                SPIRE_STRESS_FOREVER: "0",
                SPIRE_STRESS_ROUNDS: String(opts.walls),
                SPIRE_STRESS_WEB: "0",
                SPIRE_STRESS_OPEN_BROWSER: "0",
                SPIRE_STRESS_LOAD_MODE: opts.loadPacing,
                /** Parent merges facet JSON after the matrix; suppress per-child stdout table. */
                SPIRE_STRESS_FACET_DEFER: "1",
                SPIRE_STRESS_FACET_REPORT: "0",
                SPIRE_STRESS_FACET_DUMP_PATH: dumpPath,
                NODE_ENV: process.env["NODE_ENV"] ?? "development",
            };
            if (opts.seconds !== undefined) {
                env["SPIRE_STRESS_MAX_WALL_SEC"] = String(opts.seconds);
            }
            if (opts.host !== undefined) {
                env["SPIRE_STRESS_HOST"] = opts.host;
            }
            if (opts.burstGapMs !== undefined) {
                env["SPIRE_STRESS_BURST_GAP_MS"] = opts.burstGapMs;
            }

            const code = await runChild(env);
            worst = Math.max(worst, code);
            rows.push(
                `${String(combo)}\t${String(c)}\t${String(n)}\t${String(code)}`,
            );
            if (opts.stopOnFail && code === 1) {
                process.stderr.write(
                    "\nstress:cli: stopping (--stop-on-fail) after exit code 1.\n",
                );
                break matrix;
            }
            if (code === 2) {
                process.stderr.write(
                    "\nstress:cli: target unreachable (exit 2) — aborting matrix.\n",
                );
                process.stderr.write(rows.join("\n") + "\n");
                process.exit(2);
            }
        }
    }

    let hostForReport =
        opts.host?.trim() ??
        process.env["SPIRE_STRESS_HOST"]?.trim() ??
        "127.0.0.1:16777";
    const rowLists: StressUiFacetRow[][] = [];
    for (const p of facetDumpPaths) {
        try {
            const raw = readFileSync(p, "utf8");
            const j = parseFacetDumpFile(raw);
            if (j !== null) {
                if (j.host.length > 0) {
                    hostForReport = j.host;
                }
                rowLists.push(j.facets);
            }
        } catch {
            /* combo may have crashed before write */
        }
        try {
            unlinkSync(p);
        } catch {
            /* ignore */
        }
    }
    if (rowLists.length > 0) {
        const merged = mergeStressFacetRowLists(rowLists);
        const headline = `stress:cli matrix · ${String(rowLists.length)} run(s) · scenario=${opts.scenario} · target=${hostForReport} · clients ${opts.clients.join(",")} · conc ${opts.conc.join(",")}`;
        process.stdout.write(
            formatStressFacetCiReport(
                {
                    scenario: opts.scenario,
                    host: hostForReport,
                    facets: merged,
                },
                { headline },
            ),
        );
    }

    process.stderr.write("\n" + rows.join("\n") + "\n\n");
    process.stderr.write(`stress:cli: worst exit code ${String(worst)}\n`);
    process.exit(worst <= 1 ? worst : worst === 2 ? 2 : 1);
}

void main().catch((err: unknown) => {
    process.stderr.write(err instanceof Error ? err.message : String(err));
    process.stderr.write("\n");
    process.exit(1);
});
