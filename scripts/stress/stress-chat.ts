/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Chat-shaped load: WebSocket + one shared server/channel + mixed reads, group
 * sends, DMs, and history fetches (so other members exercise the same paths as
 * real recipients).
 */
import type { Client } from "@vex-chat/libvex";

import { randomInt, randomUUID } from "node:crypto";

import { allTracked, type HttpExpectStats } from "./stress-http-stats.ts";
import { shortId } from "./stress-request-context.ts";
import {
    settleWithTelemetry,
    type StressTelemetry,
    type TelemetryTouchCtx,
} from "./stress-telemetry.ts";

export interface ChatWorld {
    readonly channelID: string;
    readonly serverID: string;
    readonly userIDs: readonly string[];
}

const DURATIONS = ["1h", "24h", "48h", "7d"] as const;

function pickDuration(): string {
    return DURATIONS[randomInt(0, DURATIONS.length)] ?? "24h";
}

function pickPeerUserID(world: ChatWorld, clientIndex: number): string | null {
    const choices = world.userIDs.filter((_id, i) => i !== clientIndex);
    if (choices.length === 0) {
        return null;
    }
    return choices[randomInt(0, choices.length)] ?? null;
}

function touchCtx(
    phase: string,
    burst: number,
    clientIndex: number,
): TelemetryTouchCtx {
    return { burst, clientIndex, phase };
}

/**
 * Hub creates one server, invites every other client (same pattern as noise),
 * so all stress clients share #general instead of each living on its own server.
 */
export async function bootstrapChatWorld(
    clients: Client[],
    stats: HttpExpectStats,
    telemetry: StressTelemetry | null,
    phase: string,
    burst: number,
): Promise<ChatWorld> {
    if (clients.length === 0) {
        throw new Error("chat: need at least one client.");
    }
    const hub = clients[0];
    if (hub === undefined) {
        throw new Error("chat: hub client missing.");
    }
    const base = touchCtx(phase, burst, 0);
    const serverName = `stress-chat-${randomUUID().replace(/-/g, "").slice(0, 10)}`;
    const server = await settleWithTelemetry(
        stats,
        telemetry,
        "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
        base,
        hub.servers.create(serverName),
        { inputs: { serverName } },
    );
    const channelList = await settleWithTelemetry(
        stats,
        telemetry,
        "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
        base,
        hub.channels.retrieve(server.serverID),
        { inputs: { serverID: shortId(server.serverID) } },
    );
    const primary =
        channelList.find((c) => c.name === "general") ?? channelList[0];
    if (primary === undefined) {
        throw new Error("chat: server has no channels.");
    }

    for (let i = 1; i < clients.length; i++) {
        const guest = clients[i];
        if (guest === undefined) {
            throw new Error("chat: guest client missing.");
        }
        const inviteDuration = pickDuration();
        const inv = await settleWithTelemetry(
            stats,
            telemetry,
            "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
            { ...base, clientIndex: i },
            hub.invites.create(server.serverID, inviteDuration),
            {
                inputs: {
                    clientIndex: i,
                    duration: inviteDuration,
                    serverID: shortId(server.serverID),
                },
            },
        );
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
            { ...base, clientIndex: i },
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
        clients.map((c, i) =>
            settleWithTelemetry(
                stats,
                telemetry,
                "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
                { ...base, clientIndex: i },
                c.whoami(),
                { inputs: { clientIndex: i, step: "whoami_world_bootstrap" } },
            ),
        ),
    );
    const userIDs = meta.map((m) => m.user.userID);

    return {
        channelID: primary.channelID,
        serverID: server.serverID,
        userIDs,
    };
}

export async function oneChatOp(
    client: Client,
    world: ChatWorld,
    clientIndex: number,
    slot: number,
    stats: HttpExpectStats,
    telemetry: StressTelemetry | null,
    phase: string,
    burst: number,
): Promise<void> {
    const ctx = touchCtx(phase, burst, clientIndex);
    const m = slot % 10;
    if (m === 0 || m === 1) {
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.messages.group | chat",
            ctx,
            client.messages.group(
                world.channelID,
                `[stress] c${String(clientIndex)} s${String(slot)}-${Date.now().toString(36)}`,
            ),
            {
                inputs: {
                    channelID: shortId(world.channelID),
                    serverID: shortId(world.serverID),
                    slot,
                },
            },
        );
        return;
    }
    if (m === 2) {
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.messages.retrieveGroup | chat",
            ctx,
            client.messages.retrieveGroup(world.channelID),
            {
                inputs: {
                    channelID: shortId(world.channelID),
                    slot,
                },
            },
        );
        return;
    }
    if (m === 3) {
        const peer = pickPeerUserID(world, clientIndex);
        if (peer === null) {
            await settleWithTelemetry(
                stats,
                telemetry,
                "Client.whoami | chat",
                ctx,
                client.whoami(),
                { inputs: { reason: "no_peer_for_dm", slot } },
            );
            return;
        }
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.messages.send | chat",
            ctx,
            client.messages.send(
                peer,
                `[stress-dm] c${String(clientIndex)}-${Date.now().toString(36)}`,
            ),
            {
                inputs: {
                    peerUserID: shortId(peer),
                    slot,
                },
            },
        );
        return;
    }
    if (m === 4) {
        const peer = pickPeerUserID(world, clientIndex);
        if (peer === null) {
            await settleWithTelemetry(
                stats,
                telemetry,
                "Client.whoami | chat",
                ctx,
                client.whoami(),
                { inputs: { reason: "no_peer_for_dm_hist", slot } },
            );
            return;
        }
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.messages.retrieve | chat",
            ctx,
            client.messages.retrieve(peer),
            { inputs: { peerUserID: shortId(peer), slot } },
        );
        return;
    }
    if (m === 5) {
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.servers.retrieve | chat",
            ctx,
            client.servers.retrieve(),
            { inputs: { slot } },
        );
        return;
    }
    if (m === 6) {
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.permissions.retrieve | chat",
            ctx,
            client.permissions.retrieve(),
            { inputs: { slot } },
        );
        return;
    }
    if (m === 7) {
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.channels.retrieve | chat",
            ctx,
            client.channels.retrieve(world.serverID),
            { inputs: { serverID: shortId(world.serverID), slot } },
        );
        return;
    }
    if (m === 8) {
        await settleWithTelemetry(
            stats,
            telemetry,
            "Client.channels.userList | chat",
            ctx,
            client.channels.userList(world.channelID),
            {
                inputs: {
                    channelID: shortId(world.channelID),
                    slot,
                },
            },
        );
        return;
    }
    await settleWithTelemetry(
        stats,
        telemetry,
        "Client.servers.retrieveByID | chat",
        ctx,
        client.servers.retrieveByID(world.serverID),
        { inputs: { serverID: shortId(world.serverID), slot } },
    );
}

export async function oneChatBurst(
    client: Client,
    clientIndex: number,
    world: ChatWorld,
    n: number,
    stats: HttpExpectStats,
    telemetry: StressTelemetry | null,
    phase: string,
    burst: number,
): Promise<void> {
    await allTracked(
        stats,
        Array.from({ length: n }, (_, i) =>
            oneChatOp(
                client,
                world,
                clientIndex,
                i,
                stats,
                telemetry,
                phase,
                burst,
            ),
        ),
    );
}
