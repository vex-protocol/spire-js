#!/usr/bin/env node
/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 *
 * Add or verify the standard Vex copyright block in tracked source files.
 *
 * Usage:
 *   node scripts/copyright-headers.mjs           # prepend header where missing
 *   node scripts/copyright-headers.mjs --check   # exit 1 if any file is missing the header
 */

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const REPO_NAME = path.basename(ROOT);

const HEADER = `/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

`;

/** @returns {{ dir: string, exts: Set<string> }[]} */
function patternsForRepo(repo) {
    if (repo === "spire-js") {
        return [
            { dir: path.join(ROOT, "src"), exts: new Set([".ts"]) },
            {
                dir: path.join(ROOT, "scripts"),
                exts: new Set([".ts", ".js", ".mjs"]),
            },
            { dir: path.join(ROOT, "services"), exts: new Set([".js"]) },
        ];
    }
    if (repo === "libvex-js" || repo === "crypto-js") {
        return [{ dir: path.join(ROOT, "src"), exts: new Set([".ts"]) }];
    }
    console.error(
        `copyright-headers: unknown repo folder "${repo}" (expected spire-js, libvex-js, or crypto-js).`,
    );
    process.exit(1);
}

/**
 * @param {string} dir
 * @param {Set<string>} exts
 * @param {string[]} out
 */
async function collectFiles(dir, exts, out) {
    let entries;
    try {
        entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
        return;
    }
    for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
            await collectFiles(full, exts, out);
        } else if (exts.has(path.extname(e.name))) {
            out.push(full);
        }
    }
}

/**
 * @param {string} raw
 * @returns {string | null} error message or null if ok
 */
function checkHeader(raw) {
    const body = raw.replace(/^#![^\n]*\r?\n/, "");
    const head = body.slice(0, 2500);
    if (
        !/Copyright \(c\) 20\d{2}(-20\d{2})? Vex Heavy Industries LLC/.test(
            head,
        )
    ) {
        return "missing or invalid Copyright (c) … Vex Heavy Industries LLC line near top of file";
    }
    if (!head.includes("Licensed under AGPL-3.0")) {
        return 'missing "Licensed under AGPL-3.0" in header';
    }
    if (!head.includes("Commercial licenses available at vex.wtf")) {
        return 'missing "Commercial licenses available at vex.wtf" in header';
    }
    return null;
}

/**
 * @param {string} filePath
 */
async function prependHeader(filePath) {
    const raw = await fs.readFile(filePath, "utf8");
    if (checkHeader(raw) === null) {
        return "skip";
    }
    const shebang = raw.match(/^#![^\n]*\r?\n/);
    let body = raw;
    let prefix = "";
    if (shebang) {
        prefix = shebang[0];
        body = raw.slice(shebang[0].length);
    }
    await fs.writeFile(filePath, prefix + HEADER + body, "utf8");
    return "ok";
}

async function main() {
    const check = process.argv.includes("--check");
    const specs = patternsForRepo(REPO_NAME);
    const files = [];
    for (const { dir, exts } of specs) {
        await collectFiles(dir, exts, files);
    }
    files.sort();

    if (check) {
        const failures = [];
        for (const f of files) {
            const raw = await fs.readFile(f, "utf8");
            const err = checkHeader(raw);
            if (err) {
                failures.push({ f, err });
            }
        }
        if (failures.length > 0) {
            console.error("Copyright header check failed:\n");
            for (const { f, err } of failures) {
                console.error(`  ${path.relative(ROOT, f)}: ${err}`);
            }
            console.error(
                `\nFix: run \`node scripts/copyright-headers.mjs\` in this repo (or \`npm run copyright:apply\` if defined), then commit.`,
            );
            process.exit(1);
        }
        console.log(`Copyright header check: OK (${files.length} files).`);
        return;
    }

    let ok = 0;
    let skipped = 0;
    for (const f of files) {
        const r = await prependHeader(f);
        if (r === "ok") {
            ok++;
            console.log(`+ ${path.relative(ROOT, f)}`);
        } else {
            skipped++;
        }
    }
    console.log(`Done: ${ok} updated, ${skipped} already OK.`);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
