/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { StressLoadPacing } from "./stress-load-pacing.ts";

/**
 * Queues a stress harness restart from the web UI (applied between flood walls).
 */
export interface StressWebRestartRequest {
    readonly burstGapMs?: number;
    readonly clientCount: number;
    readonly concurrency: number;
    /** @see parseStressLoadPacing */
    readonly loadPacing: StressLoadPacing;
}

export class StressRestartQueue {
    private pending: StressWebRestartRequest | null = null;

    public schedule(req: StressWebRestartRequest): void {
        this.pending = req;
    }

    /** Take the pending restart, if any (single consumer). */
    public consume(): StressWebRestartRequest | null {
        const p = this.pending;
        this.pending = null;
        return p;
    }

    public peek(): StressWebRestartRequest | null {
        return this.pending;
    }
}
