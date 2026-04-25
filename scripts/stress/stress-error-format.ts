/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { inspect } from "node:util";

/**
 * Rich stderr for unhandled stress harness errors (Spire 5 JSON bodies, axios metadata).
 */
import { isAxiosError } from "axios";

const MAX_SNIP = 6_000;

function isRecord(x: unknown): x is Record<string, unknown> {
    return typeof x === "object" && x !== null;
}

/**
 * Spire's error handler returns JSON `{ "error": { "message", "requestId"?, … } }`.
 * Some call sites only have the raw string on `Error.message` — try to pretty-print.
 */
function linesFromErrorMessageString(msg: string): string[] | null {
    const t = msg.trim();
    if (!t.startsWith("{")) {
        return null;
    }
    let raw: unknown;
    try {
        // JSON.parse is typed as any; assign into unknown for safe narrowing.
        const parsed: unknown = JSON.parse(t);
        raw = parsed;
    } catch {
        return null;
    }
    if (!isRecord(raw)) {
        return null;
    }
    const errField = raw["error"];
    if (!isRecord(errField)) {
        return null;
    }
    const message = errField["message"];
    if (typeof message !== "string") {
        return null;
    }
    const out: string[] = [];
    out.push(`  body.message: ${message}`);
    const requestId = errField["requestId"];
    if (typeof requestId === "string" && requestId.length > 0) {
        out.push(`  body.requestId: ${requestId}`);
    }
    if (errField["details"] !== undefined) {
        const s = JSON.stringify(errField["details"]);
        out.push(
            `  body.details: ${s.length > 2_000 ? s.slice(0, 2_000) + "…" : s}`,
        );
    }
    return out;
}

/**
 * Use in `spire-stress` top-level `catch` so CI logs are actionable (not one opaque line).
 */
export function formatStressUncaughtError(err: unknown): string {
    if (isAxiosError(err)) {
        const lines: string[] = ["[axios]"];
        if (err.response) {
            const r = err.response;
            const st = String(r.status);
            lines.push(`  status: ${st} ${r.statusText}`.trim());
            const cfg = r.config;
            const method = (cfg.method ?? "?").toUpperCase();
            const base = cfg.baseURL ?? "";
            const path = cfg.url ?? "";
            lines.push(`  request: ${method} ${base}${path}`);
            if (r.data !== undefined) {
                let d: string;
                if (r.data instanceof ArrayBuffer) {
                    d = new TextDecoder("utf-8", { fatal: false }).decode(
                        new Uint8Array(r.data),
                    );
                } else if (r.data instanceof Uint8Array) {
                    d = new TextDecoder("utf-8", { fatal: false }).decode(
                        r.data,
                    );
                } else if (typeof r.data === "string") {
                    d = r.data;
                } else {
                    try {
                        d = JSON.stringify(r.data);
                    } catch {
                        d = String(r.data);
                    }
                }
                d = d.length > MAX_SNIP ? d.slice(0, MAX_SNIP) + "…" : d;
                lines.push(`  response (utf-8 / json): ${d}`);
            }
        } else {
            lines.push("  (no response — network / DNS / connection refused?)");
        }
        lines.push(`  axios.message: ${err.message}`);
        if (err.code !== undefined) {
            lines.push(`  code: ${err.code}`);
        }
        return lines.join("\n");
    }

    if (err instanceof Error) {
        const fromMsg = linesFromErrorMessageString(err.message);
        if (fromMsg !== null) {
            return [
                "[Error] (message looked like Spire JSON body)",
                ...fromMsg,
                `  name: ${err.name}`,
            ].join("\n");
        }
        return [
            "[Error]",
            `  name: ${err.name}`,
            `  message: ${err.message}`,
            err.stack
                ? `  stack (first 3k): ${err.stack.slice(0, 3_000)}${err.stack.length > 3_000 ? "…" : ""}`
                : "",
        ]
            .filter((l) => l.length > 0)
            .join("\n");
    }

    return inspect(err, { colors: false, depth: 6, maxStringLength: 2_000 });
}
