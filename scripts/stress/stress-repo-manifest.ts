/**
 * Build a compact file index of local source trees for LLM / issue triage.
 * Does not embed full repo text (too large for one context); use paths + hashes
 * so a model can ask to open specific files or you can attach slices manually.
 *
 * @example From spire-js:
 *   node --experimental-strip-types scripts/stress/stress-repo-manifest.ts
 *
 * Env:
 *   STRESS_MANIFEST_OUT — output path (default ~/.spire-stress/repo-manifest.json)
 *   STRESS_MANIFEST_ROOTS — comma-separated dirs relative to cwd (default:
 *     src,scripts/stress,../libvex-js/src)
 */
import { createHash } from "node:crypto";
import {
    mkdirSync,
    readdirSync,
    readFileSync,
    statSync,
    writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";

const DEFAULT_OUT = join(homedir(), ".spire-stress", "repo-manifest.json");

interface ManifestFile {
    readonly lines: number;
    readonly path: string;
    readonly sha256: string;
    readonly size: number;
}

function walkTsFiles(
    rootAbs: string,
    relBase: string,
    out: ManifestFile[],
): void {
    let entries: string[];
    try {
        entries = readdirSync(rootAbs);
    } catch {
        return;
    }
    for (const name of entries) {
        if (name === "node_modules" || name === "dist" || name === ".git") {
            continue;
        }
        const abs = join(rootAbs, name);
        let st: ReturnType<typeof statSync>;
        try {
            st = statSync(abs);
        } catch {
            continue;
        }
        const rel = join(relBase, name);
        if (st.isDirectory()) {
            walkTsFiles(abs, rel, out);
        } else if (
            st.isFile() &&
            (name.endsWith(".ts") || name.endsWith(".tsx"))
        ) {
            let buf: Buffer;
            try {
                buf = readFileSync(abs);
            } catch {
                continue;
            }
            const text = buf.toString("utf8");
            const lines = text.length === 0 ? 0 : text.split("\n").length;
            const sha256 = createHash("sha256").update(buf).digest("hex");
            out.push({
                lines,
                path: rel.split("\\").join("/"),
                sha256,
                size: buf.length,
            });
        }
    }
}

function main(): void {
    const cwd = process.cwd();
    const rawRoots =
        process.env["STRESS_MANIFEST_ROOTS"]?.trim() ??
        "src,scripts/stress,../libvex-js/src";
    const roots = rawRoots
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
    const outPath = process.env["STRESS_MANIFEST_OUT"]?.trim() || DEFAULT_OUT;

    const files: ManifestFile[] = [];
    for (const r of roots) {
        const abs = resolve(cwd, r);
        try {
            if (!statSync(abs).isDirectory()) {
                continue;
            }
        } catch {
            continue;
        }
        const relBase = relative(cwd, abs) || r;
        walkTsFiles(abs, relBase, files);
    }
    files.sort((a, b) => a.path.localeCompare(b.path));

    const payload = {
        cwd,
        files,
        generatedAt: new Date().toISOString(),
        note: "Paths are relative to cwd. Full-file bodies are not included; attach slices per incident or use your editor/IDE.",
        roots,
        schema: "spire-stress-repo-manifest@1",
        totalBytes: files.reduce((s, f) => s + f.size, 0),
        totalFiles: files.length,
    };

    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    process.stderr.write(`Wrote ${outPath} (${String(files.length)} files).\n`);
}

main();
