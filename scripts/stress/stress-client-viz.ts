/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/** Per-client row for the stress dashboard (last op + health). */
export interface StressClientViz {
    /** Sub-step currently running (for crashes outside our try/catch). */
    inFlight: string;
    lastOk: boolean;
    lastOp: string;
    ops: number;
}

export function createStressClientViz(clientCount: number): StressClientViz[] {
    return Array.from({ length: clientCount }, () => ({
        inFlight: "",
        lastOk: true,
        lastOp: "—",
        ops: 0,
    }));
}
