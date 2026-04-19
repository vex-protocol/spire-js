/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Sanitize and label libvex / harness request context for telemetry + LLM bundles.
 */
import {
    normalizeStressSurfaceKey,
    protocolPathForStressFacet,
    STRESS_FACET_CATALOG,
} from "./stress-api-catalog.ts";

const REDACT_KEYS =
    /password|passwd|token|secret|authorization|apikey|api_key|cipher|hmac|sk\b|privatekey|private_key/i;

const MAX_STRING = 240;
const MAX_DEPTH = 5;

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** First `Client.*` segment from catalog `protocolPath` (before `;`) for compact labels. */
export function facetToLibvexSurface(surfaceKey: string): string {
    const key = normalizeStressSurfaceKey(surfaceKey);
    const e = STRESS_FACET_CATALOG[key];
    if (e !== undefined) {
        const parts = e.protocolPath.split(";");
        const first = parts[0]?.trim();
        if (first !== undefined && first.length > 0) {
            return first;
        }
    }
    const p = protocolPathForStressFacet(surfaceKey);
    const seg = p.split(";")[0]?.trim();
    return seg !== undefined && seg.length > 0 ? seg : p;
}

/** First catalog `Client.*` segment (before `;`) for synthetic call notation. */
export function firstClientProtocolCall(protocolPath: string): string {
    const first = protocolPath.split(";")[0]?.trim();
    return first !== undefined && first.length > 0
        ? first
        : protocolPath.trim();
}

/**
 * JavaScript-style call label for telemetry: `Client.foo.bar({ ...args })`.
 * Uses sanitized `requestInputs` only.
 */
export function formatHarnessCallNotation(
    protocolPath: string,
    requestInputs?: Readonly<Record<string, unknown>> | null,
): string | undefined {
    const head = firstClientProtocolCall(protocolPath);
    if (head.length === 0) {
        return undefined;
    }
    if (requestInputs === undefined || requestInputs === null) {
        return `${head}()`;
    }
    const keys = Object.keys(requestInputs);
    if (keys.length === 0) {
        return `${head}()`;
    }
    try {
        const body = JSON.stringify(requestInputs, null, 2);
        const cap = 2800;
        const arg =
            body.length > cap
                ? `${body.slice(0, cap)}\n/* …truncated (${String(body.length)} chars) … */`
                : body;
        return `${head}(\n${arg}\n)`;
    } catch {
        return `${head}(/* [unserializable requestInputs] */)`;
    }
}

function sanitizeValue(value: unknown, depth: number): unknown {
    if (depth > MAX_DEPTH) {
        return "[max-depth]";
    }
    if (value === null || value === undefined) {
        return value;
    }
    if (typeof value === "string") {
        return value.length > MAX_STRING
            ? `${value.slice(0, MAX_STRING)}…`
            : value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
        return value;
    }
    if (typeof value === "bigint") {
        return value.toString();
    }
    if (value instanceof Uint8Array) {
        return { _type: "Uint8Array", byteLength: value.byteLength };
    }
    if (Array.isArray(value)) {
        return value.slice(0, 24).map((v) => sanitizeValue(v, depth + 1));
    }
    if (isPlainObject(value)) {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value)) {
            if (REDACT_KEYS.test(k)) {
                out[k] = "«redacted»";
            } else {
                out[k] = sanitizeValue(v, depth + 1);
            }
        }
        return out;
    }
    return `[${typeof value}]`;
}

/** JSON-safe, redacted copy for telemetry / issue bundles. */
export function sanitizeRequestInputs(
    inputs: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
    const out = sanitizeValue(inputs, 0);
    if (isPlainObject(out)) {
        return { ...out };
    }
    return { value: out };
}

/** Shorten ids for display while keeping some entropy for correlation debugging. */
export function shortId(id: string, keep = 10): string {
    if (id.length <= keep + 2) {
        return id;
    }
    return `${id.slice(0, keep)}…`;
}
