/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Crypto-RNG–driven multi-client load: exercises a broad slice of libvex + Spire.
 * Assumes distinct registered users per Client (see spire-stress guard).
 */
import type { StressClientViz } from "./stress-client-viz.ts";
import type { StressCrashContext } from "./stress-crash-dump.ts";
import type { StressTraceDb } from "./stress-trace-db.ts";
import type { Client } from "@vex-chat/libvex";

import { Buffer } from "node:buffer";
import { randomBytes, randomInt, randomUUID } from "node:crypto";

import {
    protocolPathForStressFacet,
    surfaceKeyForNoiseOpId,
} from "./stress-api-catalog.ts";
import {
    type HttpExpectStats,
    recordHttpFailure,
    trackSoftResult,
    type TrackSoftResult,
} from "./stress-http-stats.ts";
import { shortId } from "./stress-request-context.ts";
import {
    settleWithTelemetry,
    type StressTelemetry,
    type TelemetryTouchCtx,
} from "./stress-telemetry.ts";

/** Smallest valid PNG (1×1). */
const TINY_PNG = new Uint8Array(
    Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/l1G8QAAAABJRU5ErkJggg==",
        "base64",
    ),
);

export interface NoiseWorld {
    readonly channelID: string;
    readonly serverID: string;
    readonly userIDs: readonly string[];
    readonly usernames: readonly string[];
}

const DURATIONS = ["1h", "24h", "48h", "7d"] as const;

function pickDuration(): string {
    return DURATIONS[randomInt(0, DURATIONS.length)] ?? "24h";
}

function randomMsg(): string {
    const tag = randomBytes(4).toString("hex");
    return `[noise ${tag}] ${String(randomInt(0, 1_000_000))}`;
}

function pickPeerUserID(world: NoiseWorld, clientIndex: number): string | null {
    const choices = world.userIDs.filter((_id, i) => i !== clientIndex);
    if (choices.length === 0) {
        return null;
    }
    return choices[randomInt(0, choices.length)] ?? null;
}

function pickPeerUsername(
    world: NoiseWorld,
    clientIndex: number,
): string | null {
    const choices = world.usernames.filter((_u, i) => i !== clientIndex);
    if (choices.length === 0) {
        return null;
    }
    return choices[randomInt(0, choices.length)] ?? null;
}

/** Hub creates shared server, invites everyone else, then all WS connect. */
export async function bootstrapNoiseWorld(
    clients: Client[],
    stats: HttpExpectStats,
    trace: StressTraceDb | null,
    crashCtx: StressCrashContext,
    telemetry: StressTelemetry | null,
): Promise<NoiseWorld> {
    if (clients.length === 0) {
        throw new Error("noise: need at least one client.");
    }
    const hub = clients[0];
    if (hub === undefined) {
        throw new Error("noise: hub client missing.");
    }
    const tCtx: TelemetryTouchCtx = {
        burst: crashCtx.currentBurst,
        phase: crashCtx.phase,
    };
    const serverLabel = `noise-${randomUUID().replace(/-/g, "").slice(0, 10)}`;
    const server = await settleWithTelemetry(
        stats,
        telemetry,
        "Client.servers.create; Client.channels.retrieve",
        tCtx,
        hub.servers.create(serverLabel),
        { inputs: { serverLabel } },
    );
    const channelList = await settleWithTelemetry(
        stats,
        telemetry,
        "Client.servers.create; Client.channels.retrieve",
        tCtx,
        hub.channels.retrieve(server.serverID),
        { inputs: { serverID: shortId(server.serverID) } },
    );
    const primary =
        channelList.find((c) => c.name === "general") ?? channelList[0];
    if (primary === undefined) {
        throw new Error("noise: server has no channels.");
    }

    for (let i = 1; i < clients.length; i++) {
        const guest = clients[i];
        if (guest === undefined) {
            throw new Error("noise: guest client missing.");
        }
        const noiseInviteDuration = pickDuration();
        const inv = await settleWithTelemetry(
            stats,
            telemetry,
            "Client.invites.create; Client.invites.redeem | world guests",
            { ...tCtx, clientIndex: i },
            hub.invites.create(server.serverID, noiseInviteDuration),
            {
                inputs: {
                    clientIndex: i,
                    duration: noiseInviteDuration,
                    serverID: shortId(server.serverID),
                },
            },
        );
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.invites.create; Client.invites.redeem | world guests",
            { ...tCtx, clientIndex: i },
            guest.invites.redeem(inv.inviteID),
            {
                inputs: {
                    clientIndex: i,
                    inviteID: shortId(inv.inviteID),
                    serverID: shortId(server.serverID),
                },
            },
        );
    }

    const meta = await Promise.all(
        clients.map((c, idx) =>
            settleWithTelemetry(
                stats,
                telemetry,
                "Client.whoami",
                { ...tCtx, clientIndex: idx },
                c.whoami(),
                { inputs: { clientIndex: idx, step: "noise_world_whoami" } },
            ),
        ),
    );
    const userIDs = meta.map((m) => m.user.userID);
    const usernames = meta.map((m) => m.user.username);

    await Promise.all(
        clients.map((c, idx) =>
            settleWithTelemetry(
                stats,
                telemetry,
                "Client.connect | websocket mesh",
                { ...tCtx, clientIndex: idx },
                c.connect(),
                { inputs: { clientIndex: idx } },
            ),
        ),
    );

    const world: NoiseWorld = {
        channelID: primary.channelID,
        serverID: server.serverID,
        userIDs,
        usernames,
    };
    trace?.append({
        burst: crashCtx.currentBurst,
        detail: {
            channelID: world.channelID,
            clientCount: clients.length,
            serverID: world.serverID,
            usernames: [...world.usernames],
        },
        event: "noise_world_ready",
        phase: crashCtx.phase,
    });
    return world;
}

/** Noise op outcome; `cause` is the libvex/axios rejection when the Client path threw. */
export type NoiseOpOutcome = TrackSoftResult;

type OpFn = (
    client: Client,
    clientIndex: number,
    world: NoiseWorld,
    stats: HttpExpectStats,
) => Promise<NoiseOpOutcome>;

function noiseTelemetryErr(
    surfaceKey: string,
    outcome: NoiseOpOutcome,
): unknown {
    if (outcome.ok) {
        return new Error("noiseTelemetryErr: unexpected ok outcome");
    }
    if (outcome.cause instanceof Error) {
        return outcome.cause;
    }
    if (outcome.cause !== undefined && outcome.cause !== null) {
        const c = outcome.cause;
        const msg =
            typeof c === "string"
                ? c
                : c instanceof Error
                  ? c.message
                  : JSON.stringify(c);
        return new Error(msg);
    }
    return new Error(
        `${protocolPathForStressFacet(surfaceKey)} — soft-fail (runner swallowed rejection)`,
    );
}

const WEIGHTED_OPS: readonly { run: OpFn; w: number; id: string }[] = [
    {
        id: "grp_msg",
        w: 16,
        run: async (client, _i, world, stats) =>
            trackSoftResult(
                stats,
                client.messages.group(world.channelID, randomMsg()),
            ),
    },
    {
        id: "grp_hist",
        w: 7,
        run: async (client, _i, world, stats) =>
            trackSoftResult(
                stats,
                client.messages.retrieveGroup(world.channelID),
            ),
    },
    {
        id: "dm_send",
        w: 10,
        run: async (client, idx, world, stats) => {
            const peer = pickPeerUserID(world, idx);
            if (peer === null) {
                return trackSoftResult(stats, client.whoami());
            }
            return trackSoftResult(
                stats,
                client.messages.send(peer, randomMsg()),
            );
        },
    },
    {
        id: "dm_hist",
        w: 5,
        run: async (client, idx, world, stats) => {
            const peer = pickPeerUserID(world, idx);
            if (peer === null) {
                return trackSoftResult(stats, client.servers.retrieve());
            }
            return trackSoftResult(stats, client.messages.retrieve(peer));
        },
    },
    {
        id: "whoami",
        w: 4,
        run: async (client, _i, _w, stats) =>
            trackSoftResult(stats, client.whoami()),
    },
    {
        id: "srv_list",
        w: 5,
        run: async (client, _i, _w, stats) =>
            trackSoftResult(stats, client.servers.retrieve()),
    },
    {
        id: "srv_id",
        w: 4,
        run: async (client, _i, world, stats) =>
            trackSoftResult(stats, client.servers.retrieveByID(world.serverID)),
    },
    {
        id: "perm_me",
        w: 5,
        run: async (client, _i, _w, stats) =>
            trackSoftResult(stats, client.permissions.retrieve()),
    },
    {
        id: "ch_list",
        w: 5,
        run: async (client, _i, world, stats) =>
            trackSoftResult(stats, client.channels.retrieve(world.serverID)),
    },
    {
        id: "ch_id",
        w: 4,
        run: async (client, _i, world, stats) =>
            trackSoftResult(
                stats,
                client.channels.retrieveByID(world.channelID),
            ),
    },
    {
        id: "ch_users",
        w: 6,
        run: async (client, _i, world, stats) =>
            trackSoftResult(stats, client.channels.userList(world.channelID)),
    },
    {
        id: "fam",
        w: 4,
        run: async (client, _i, _w, stats) =>
            trackSoftResult(stats, client.users.familiars()),
    },
    {
        id: "usr_get",
        w: 5,
        run: async (client, idx, world, stats) => {
            const u = pickPeerUsername(world, idx);
            if (u === null) {
                return trackSoftResult(stats, client.whoami());
            }
            try {
                const [user, err] = await client.users.retrieve(u);
                if (err) {
                    recordHttpFailure(stats, err);
                    return { ok: false, cause: err };
                }
                if (user === null) {
                    const empty = new Error("users.retrieve returned empty");
                    recordHttpFailure(stats, empty);
                    return { ok: false, cause: empty };
                }
                stats.ok += 1;
                return { ok: true };
            } catch (err: unknown) {
                recordHttpFailure(stats, err);
                return { ok: false, cause: err };
            }
        },
    },
    {
        id: "sess",
        w: 4,
        run: async (client, _i, _w, stats) =>
            trackSoftResult(stats, client.sessions.retrieve()),
    },
    {
        id: "me_u",
        w: 3,
        run: async (client, _i, _w, stats) => {
            void client.me.user();
            return trackSoftResult(stats, client.whoami());
        },
    },
    {
        id: "me_dev",
        w: 3,
        run: async (client, _i, _w, stats) => {
            void client.me.device();
            return trackSoftResult(stats, client.whoami());
        },
    },
    {
        id: "mod_list",
        w: 4,
        run: async (client, _i, world, stats) =>
            trackSoftResult(
                stats,
                client.moderation.fetchPermissionList(world.serverID),
            ),
    },
    {
        id: "inv_list",
        w: 3,
        run: async (client, idx, world, stats) => {
            // INVITE permission is hub-only after redeem (guests are power 0). Listing from
            // every client floods Spire with intentional 401s and hides real regressions.
            if (idx !== 0) {
                return trackSoftResult(stats, client.whoami());
            }
            return trackSoftResult(
                stats,
                client.invites.retrieve(world.serverID),
            );
        },
    },
    {
        id: "inv_mk",
        w: 2,
        run: async (client, idx, world, stats) => {
            if (idx !== 0) {
                return trackSoftResult(stats, client.whoami());
            }
            return trackSoftResult(
                stats,
                client.invites.create(world.serverID, pickDuration()),
            );
        },
    },
];

const OP_TOTAL = WEIGHTED_OPS.reduce((s, r) => s + r.w, 0);

function pickOpIndex(): number {
    if (OP_TOTAL <= 0) {
        return 0;
    }
    let r = randomInt(0, OP_TOTAL);
    for (let i = 0; i < WEIGHTED_OPS.length; i++) {
        const row = WEIGHTED_OPS[i];
        if (row === undefined) {
            break;
        }
        r -= row.w;
        if (r < 0) {
            return i;
        }
    }
    return WEIGHTED_OPS.length - 1;
}

async function runInviteRedeemNoise(
    clients: Client[],
    world: NoiseWorld,
    stats: HttpExpectStats,
): Promise<NoiseOpOutcome> {
    const hub = clients[0];
    if (hub === undefined) {
        return { ok: false };
    }
    const guestIdx = randomInt(1, clients.length);
    const guest = clients[guestIdx];
    if (guest === undefined) {
        return { ok: false };
    }
    let inviteID: string;
    try {
        const inv = await hub.invites.create(world.serverID, pickDuration());
        stats.ok += 1;
        inviteID = inv.inviteID;
    } catch (err: unknown) {
        recordHttpFailure(stats, err);
        return { ok: false, cause: err };
    }
    return trackSoftResult(stats, guest.invites.redeem(inviteID));
}

async function runOneNoiseOp(
    clients: Client[],
    clientIndex: number,
    world: NoiseWorld,
    stats: HttpExpectStats,
    viz: StressClientViz[],
    trace: StressTraceDb | null,
    crashCtx: StressCrashContext,
    telemetry: StressTelemetry | null,
): Promise<void> {
    const client = clients[clientIndex];
    if (client === undefined) {
        return;
    }
    const row = viz[clientIndex];
    if (row === undefined) {
        return;
    }

    let id = "pick";
    let outcome: NoiseOpOutcome = { ok: true };
    let peerUser: string | undefined;
    let peerName: string | undefined;

    const detailBase = (): Record<string, unknown> => ({
        channelID: world.channelID,
        clientIndex,
        serverID: world.serverID,
    });
    try {
        row.inFlight = "pick";
        if (randomInt(0, 22) === 0 && clients.length > 1) {
            id = "inv_flow";
            peerUser = undefined;
            peerName = undefined;
            row.inFlight = id;
            trace?.append({
                burst: crashCtx.currentBurst,
                clientIndex,
                detail: { ...detailBase(), op: id, stage: "start" },
                event: "noise_op",
                phase: crashCtx.phase,
            });
            outcome = await runInviteRedeemNoise(clients, world, stats);
        } else {
            const op = WEIGHTED_OPS[pickOpIndex()];
            if (op === undefined) {
                id = "noop";
                peerUser = undefined;
                peerName = undefined;
                row.inFlight = id;
                trace?.append({
                    burst: crashCtx.currentBurst,
                    clientIndex,
                    detail: { ...detailBase(), op: id, stage: "start" },
                    event: "noise_op",
                    phase: crashCtx.phase,
                });
                outcome = { ok: true };
            } else {
                id = op.id;
                peerUser =
                    id === "dm_send" || id === "dm_hist"
                        ? (pickPeerUserID(world, clientIndex) ?? undefined)
                        : undefined;
                peerName =
                    id === "usr_get"
                        ? (pickPeerUsername(world, clientIndex) ?? undefined)
                        : undefined;
                row.inFlight = id;
                trace?.append({
                    burst: crashCtx.currentBurst,
                    clientIndex,
                    detail: {
                        ...detailBase(),
                        op: id,
                        peerUser: peerUser ?? null,
                        peerUsername: peerName ?? null,
                        stage: "start",
                    },
                    event: "noise_op",
                    phase: crashCtx.phase,
                });
                outcome = await op.run(client, clientIndex, world, stats);
            }
        }
        let ok = outcome.ok;

        const noiseReqInputs: Record<string, unknown> = {
            channelID: shortId(world.channelID),
            op: id,
            serverID: shortId(world.serverID),
        };
        if (peerUser !== undefined) {
            noiseReqInputs.peerUserID = shortId(peerUser);
        }
        if (peerName !== undefined) {
            noiseReqInputs.peerUsername = peerName;
        }

        const telemetryCtx: TelemetryTouchCtx = {
            burst: crashCtx.currentBurst,
            clientIndex,
            opId: id,
            phase: crashCtx.phase,
            requestInputs: id === "noop" ? undefined : noiseReqInputs,
        };
        if (telemetry !== null && id !== "noop") {
            const surfaceKey = surfaceKeyForNoiseOpId(id);
            if (ok) {
                telemetry.touchOk(surfaceKey, telemetryCtx);
            } else {
                telemetry.touchFail(
                    surfaceKey,
                    telemetryCtx,
                    noiseTelemetryErr(surfaceKey, outcome),
                );
            }
        }

        if (ok && randomInt(0, 25) === 0) {
            row.inFlight = `${id}+emoji_list`;
            trace?.append({
                burst: crashCtx.currentBurst,
                clientIndex,
                detail: { ...detailBase(), op: id, sub: "emoji_list" },
                event: "noise_extra",
                phase: crashCtx.phase,
            });
            const ex = await trackSoftResult(
                stats,
                client.emoji.retrieveList(world.serverID),
            );
            if (!ex.ok) {
                ok = false;
                telemetry?.touchFail(
                    "Client.emoji.retrieveList",
                    {
                        ...telemetryCtx,
                        requestInputs: {
                            ...noiseReqInputs,
                            sub: "emoji_list",
                        },
                    },
                    noiseTelemetryErr("Client.emoji.retrieveList", ex),
                );
            } else {
                telemetry?.touchOk("Client.emoji.retrieveList", {
                    ...telemetryCtx,
                    requestInputs: {
                        ...noiseReqInputs,
                        sub: "emoji_list",
                    },
                });
            }
        }
        if (ok && randomInt(0, 40) === 0 && clientIndex === 0) {
            row.inFlight = `${id}+emoji_up`;
            trace?.append({
                burst: crashCtx.currentBurst,
                clientIndex,
                detail: { ...detailBase(), op: id, sub: "emoji_upload" },
                event: "noise_extra",
                phase: crashCtx.phase,
            });
            const name = `e${randomBytes(3).toString("hex")}`;
            const em = await trackSoftResult(
                stats,
                client.emoji.create(TINY_PNG, name, world.serverID),
            );
            if (!em.ok) {
                ok = false;
                telemetry?.touchFail(
                    "Client.emoji.create",
                    {
                        ...telemetryCtx,
                        requestInputs: {
                            ...noiseReqInputs,
                            emojiName: name,
                            sub: "emoji_upload",
                        },
                    },
                    noiseTelemetryErr("Client.emoji.create", em),
                );
            } else {
                telemetry?.touchOk("Client.emoji.create", {
                    ...telemetryCtx,
                    requestInputs: {
                        ...noiseReqInputs,
                        emojiName: name,
                        sub: "emoji_upload",
                    },
                });
            }
        }
        if (ok && randomInt(0, 35) === 0) {
            row.inFlight = `${id}+file`;
            trace?.append({
                burst: crashCtx.currentBurst,
                clientIndex,
                detail: { ...detailBase(), op: id, sub: "file_create" },
                event: "noise_extra",
                phase: crashCtx.phase,
            });
            const payload = randomBytes(randomInt(16, 120));
            const up = await trackSoftResult(
                stats,
                client.files.create(payload),
            );
            if (!up.ok) {
                ok = false;
                telemetry?.touchFail(
                    "Client.files.create",
                    {
                        ...telemetryCtx,
                        requestInputs: {
                            ...noiseReqInputs,
                            byteLength: payload.byteLength,
                            sub: "file_create",
                        },
                    },
                    noiseTelemetryErr("Client.files.create", up),
                );
            } else {
                telemetry?.touchOk("Client.files.create", {
                    ...telemetryCtx,
                    requestInputs: {
                        ...noiseReqInputs,
                        byteLength: payload.byteLength,
                        sub: "file_create",
                    },
                });
            }
        }
        if (ok && randomInt(0, 45) === 0 && clientIndex === 0) {
            row.inFlight = `${id}+ch_create`;
            trace?.append({
                burst: crashCtx.currentBurst,
                clientIndex,
                detail: { ...detailBase(), op: id, sub: "channel_create" },
                event: "noise_extra",
                phase: crashCtx.phase,
            });
            const chName = `x-${randomBytes(2).toString("hex")}`;
            const ch = await trackSoftResult(
                stats,
                client.channels.create(chName, world.serverID),
            );
            if (!ch.ok) {
                ok = false;
                telemetry?.touchFail(
                    "Client.channels.create",
                    {
                        ...telemetryCtx,
                        requestInputs: {
                            ...noiseReqInputs,
                            channelName: chName,
                            sub: "channel_create",
                        },
                    },
                    noiseTelemetryErr("Client.channels.create", ch),
                );
            } else {
                telemetry?.touchOk("Client.channels.create", {
                    ...telemetryCtx,
                    requestInputs: {
                        ...noiseReqInputs,
                        channelName: chName,
                        sub: "channel_create",
                    },
                });
            }
        }

        row.lastOp = id;
        row.lastOk = ok;
        row.ops += 1;
        trace?.append({
            burst: crashCtx.currentBurst,
            clientIndex,
            detail: { ...detailBase(), ok, op: id, stage: "end" },
            event: "noise_op",
            phase: crashCtx.phase,
        });
    } catch (err: unknown) {
        recordHttpFailure(stats, err);
        row.lastOk = false;
        trace?.append({
            burst: crashCtx.currentBurst,
            clientIndex,
            detail: {
                ...detailBase(),
                err: err instanceof Error ? err.message : String(err),
                stage: "threw",
            },
            event: "noise_op",
            phase: crashCtx.phase,
        });
    } finally {
        row.inFlight = "";
    }
}

export async function runNoiseBurst(
    clients: Client[],
    world: NoiseWorld,
    perClientConcurrency: number,
    stats: HttpExpectStats,
    viz: StressClientViz[],
    trace: StressTraceDb | null,
    crashCtx: StressCrashContext,
    telemetry: StressTelemetry | null,
): Promise<void> {
    trace?.append({
        burst: crashCtx.currentBurst,
        detail: {
            clients: clients.length,
            perClientConcurrency,
            serverID: world.serverID,
        },
        event: "noise_burst_batch",
        phase: crashCtx.phase,
    });
    const tasks: Promise<void>[] = [];
    for (let ci = 0; ci < clients.length; ci++) {
        for (let k = 0; k < perClientConcurrency; k++) {
            tasks.push(
                runOneNoiseOp(
                    clients,
                    ci,
                    world,
                    stats,
                    viz,
                    trace,
                    crashCtx,
                    telemetry,
                ),
            );
        }
    }
    await Promise.allSettled(tasks);
}
