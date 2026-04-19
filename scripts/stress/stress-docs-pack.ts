/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Pack trimmed markdown docs into a JSON file for stress LLM triage.
 *
 * Env:
 *   SPIRE_STRESS_DOCS_ROOT — directory to scan (default: repo ../docs if present, else ./docs)
 *   STRESS_DOCS_PACK_PATH  — output path (default ~/.spire-stress/docs-pack.json)
 *
 * @example
 *   npm run stress:docs-pack
 */
import {
    mkdirSync,
    readdirSync,
    readFileSync,
    statSync,
    writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_OUT = join(homedir(), ".spire-stress", "docs-pack.json");
const MAX_FILES = 60;
const MAX_CHARS_PER_FILE = 12_000;

function walkMd(root: string, acc: string[], depth: number): void {
    if (depth > 8 || acc.length >= MAX_FILES) {
        return;
    }
    let names: string[];
    try {
        names = readdirSync(root);
    } catch {
        return;
    }
    for (const name of names) {
        if (acc.length >= MAX_FILES) {
            break;
        }
        if (name === "node_modules" || name.startsWith(".")) {
            continue;
        }
        const p = join(root, name);
        try {
            const st = statSync(p);
            if (st.isDirectory()) {
                walkMd(p, acc, depth + 1);
            } else if (st.isFile() && name.endsWith(".md")) {
                acc.push(p);
            }
        } catch {
            /* ignore broken symlinks */
        }
    }
}

function defaultDocsRoot(): string {
    const here = dirname(fileURLToPath(import.meta.url));
    const candidates = [
        resolve(here, "..", "..", "..", "docs"),
        resolve(here, "..", "..", "docs"),
    ];
    for (const c of candidates) {
        try {
            if (statSync(c).isDirectory()) {
                return c;
            }
        } catch {
            /* ignore */
        }
    }
    const fallback = candidates[0] ?? join(here, "..", "..", "..", "docs");
    return fallback;
}

function main(): void {
    const root =
        process.env["SPIRE_STRESS_DOCS_ROOT"]?.trim() || defaultDocsRoot();
    const outPath = process.env["STRESS_DOCS_PACK_PATH"]?.trim() || DEFAULT_OUT;

    const paths: string[] = [];
    walkMd(resolve(root), paths, 0);
    paths.sort();

    const files: { path: string; text: string; truncated: boolean }[] = [];
    for (const abs of paths) {
        let text: string;
        try {
            text = readFileSync(abs, "utf8");
        } catch {
            continue;
        }
        const truncated = text.length > MAX_CHARS_PER_FILE;
        if (truncated) {
            text = `${text.slice(0, MAX_CHARS_PER_FILE)}\n…[truncated]\n`;
        }
        files.push({
            path: relative(resolve(root), abs).replace(/\\/g, "/"),
            text,
            truncated,
        });
    }

    const payload = {
        generatedAt: new Date().toISOString(),
        root: resolve(root),
        schema: "spire-stress-docs-pack@1",
        fileCount: files.length,
        files,
    };

    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    process.stdout.write(
        `Wrote ${String(files.length)} markdown files to ${outPath}\n`,
    );
}

main();
