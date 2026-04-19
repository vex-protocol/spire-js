/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Group stress failures for issue triage: stable keys from observed fields only
 * (no guessed root causes).
 */
import { createHash } from "node:crypto";

/** First stack frame line after the message line, if present. */
export function stackSignature(stack: string | undefined): string {
    if (stack === undefined || stack.length === 0) {
        return "";
    }
    const lines = stack.split("\n").map((l) => l.trim());
    return lines.length > 1 ? (lines[1] ?? "") : "";
}

/** Collapse volatile tokens so repeated failures group together. */
export function normalizeFailureMessage(message: string): string {
    let s = message;
    s = s.replace(
        /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
        "<uuid>",
    );
    s = s.replace(/\b[0-9a-f]{16,}\b/gi, "<hex>");
    s = s.replace(/\b\d{10,}\b/g, "<n>");
    s = s.replace(/\s+/g, " ").trim();
    return s;
}

export function failureCorrelationKey(input: {
    readonly message: string;
    readonly protocolPath: string;
    readonly stack?: string;
}): string {
    const norm = normalizeFailureMessage(input.message);
    const sig = stackSignature(input.stack);
    const raw = `${input.protocolPath}\n${norm}\n${sig}`;
    return createHash("sha256").update(raw, "utf8").digest("hex").slice(0, 16);
}

export interface StressFailureGroupRow {
    readonly correlationKey: string;
    readonly count: number;
    readonly incidentIds: readonly string[];
    readonly libvexSurfaces: readonly string[];
    readonly protocolPaths: readonly string[];
    readonly sampleMessage: string;
    /** Distinct libvex surface keys (`Client.*` catalog ids) where this correlation appeared. */
    readonly surfaceKeys: readonly string[];
}

export function groupStressFailures(
    failures: readonly {
        readonly correlationKey: string;
        readonly id: string;
        readonly libvexSurface?: string;
        readonly message: string;
        readonly protocolPath?: string;
        readonly surfaceKey: string;
    }[],
): StressFailureGroupRow[] {
    const map = new Map<
        string,
        {
            count: number;
            facetSet: Set<string>;
            ids: string[];
            libvexSet: Set<string>;
            protocolSet: Set<string>;
            sampleMessage: string;
        }
    >();
    for (const f of failures) {
        const row = map.get(f.correlationKey);
        const surf = f.libvexSurface ?? "";
        const proto = f.protocolPath ?? "";
        if (row === undefined) {
            map.set(f.correlationKey, {
                count: 1,
                facetSet: new Set([f.surfaceKey]),
                ids: [f.id],
                libvexSet: new Set(surf.length > 0 ? [surf] : []),
                protocolSet: new Set(proto.length > 0 ? [proto] : []),
                sampleMessage: f.message,
            });
        } else {
            row.count += 1;
            row.facetSet.add(f.surfaceKey);
            if (surf.length > 0) {
                row.libvexSet.add(surf);
            }
            if (proto.length > 0) {
                row.protocolSet.add(proto);
            }
            if (row.ids.length < 8) {
                row.ids.push(f.id);
            }
        }
    }
    const out: StressFailureGroupRow[] = [];
    for (const [correlationKey, row] of map) {
        out.push({
            correlationKey,
            count: row.count,
            incidentIds: row.ids,
            libvexSurfaces: [...row.libvexSet].sort(),
            protocolPaths: [...row.protocolSet].sort(),
            sampleMessage: row.sampleMessage,
            surfaceKeys: [...row.facetSet].sort(),
        });
    }
    out.sort((a, b) => b.count - a.count);
    return out;
}
