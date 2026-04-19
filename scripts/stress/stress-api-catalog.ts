/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Catalog of libvex `Client.*` surfaces exercised by the stress runner.
 * Record keys are the same strings shown in telemetry and the dashboard (library-shaped),
 * not internal opcode ids.
 */
export interface StressFacetCatalogEntry {
    readonly apiCall: string;
    readonly description: string;
    readonly group: "bootstrap" | "world" | "load";
    /** Canonical libvex Client surface, e.g. `Client.invites.retrieve`. */
    readonly protocolPath: string;
    readonly title: string;
}

export const STRESS_FACET_CATALOG: Readonly<
    Record<string, StressFacetCatalogEntry>
> = {
    "Client.create": {
        apiCall: "Client.create()",
        description: "Instantiate libvex with local DB folder and Spire host.",
        group: "bootstrap",
        protocolPath: "Client.create",
        title: "Client bootstrap",
    },
    "Client.register": {
        apiCall: "client.register()",
        description: "Create a new Vex account for this stress client.",
        group: "bootstrap",
        protocolPath: "Client.register",
        title: "Register account",
    },
    "Client.login": {
        apiCall: "client.login()",
        description:
            "Authenticate session (new user or SPIRE_STRESS_USERNAME).",
        group: "bootstrap",
        protocolPath: "Client.login",
        title: "Login session",
    },
    "Client.connect": {
        apiCall: "client.connect()",
        description: "Open WebSocket to Spire for realtime mail and sync.",
        group: "bootstrap",
        protocolPath: "Client.connect",
        title: "WebSocket connect",
    },
    "Client.servers.create; Client.channels.retrieve": {
        apiCall: "servers.create · channels.retrieve",
        description: "Hub creates shared noise server and resolves #general.",
        group: "world",
        protocolPath: "Client.servers.create; Client.channels.retrieve",
        title: "Shared server + channels",
    },
    "Client.invites.create; Client.invites.redeem | world guests": {
        apiCall: "invites.create · invites.redeem",
        description: "Guests join the same guild via single-use invite links.",
        group: "world",
        protocolPath: "Client.invites.create; Client.invites.redeem",
        title: "Invite guests (world setup)",
    },
    "Client.connect | websocket mesh": {
        apiCall: "client.connect() (all clients)",
        description: "Every member opens WS after sharing the server.",
        group: "world",
        protocolPath: "Client.connect",
        title: "WebSocket mesh (noise world)",
    },
    "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami":
        {
            apiCall: "servers.create · channels.retrieve · invites.* · whoami",
            description:
                "Shared chat guild: hub server, invites, member whoami.",
            group: "world",
            protocolPath:
                "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
            title: "Chat shared server",
        },
    "Client.messages.group": {
        apiCall: "messages.group(channelID, body)",
        description: "Encrypted group post into the shared channel.",
        group: "load",
        protocolPath: "Client.messages.group",
        title: "Group message send",
    },
    "Client.messages.retrieveGroup": {
        apiCall: "messages.retrieveGroup(channelID)",
        description: "Load channel history (recipient-style read path).",
        group: "load",
        protocolPath: "Client.messages.retrieveGroup",
        title: "Group history",
    },
    "Client.messages.send": {
        apiCall: "messages.send(userID, body)",
        description: "Direct message to another stress user in the world.",
        group: "load",
        protocolPath: "Client.messages.send",
        title: "DM send",
    },
    "Client.messages.retrieve": {
        apiCall: "messages.retrieve(userID)",
        description: "DM thread history with a peer.",
        group: "load",
        protocolPath: "Client.messages.retrieve",
        title: "DM history",
    },
    "Client.whoami": {
        apiCall: "whoami()",
        description: "Resolve current user + device from Spire.",
        group: "load",
        protocolPath: "Client.whoami",
        title: "Whoami",
    },
    "Client.servers.retrieve": {
        apiCall: "servers.retrieve()",
        description: "List all servers the account belongs to.",
        group: "load",
        protocolPath: "Client.servers.retrieve",
        title: "List servers",
    },
    "Client.servers.retrieveByID": {
        apiCall: "servers.retrieveByID(serverID)",
        description: "Fetch one server record by id.",
        group: "load",
        protocolPath: "Client.servers.retrieveByID",
        title: "Server by ID",
    },
    "Client.permissions.retrieve": {
        apiCall: "permissions.retrieve()",
        description: "Permissions for the current user across servers.",
        group: "load",
        protocolPath: "Client.permissions.retrieve",
        title: "My permissions",
    },
    "Client.channels.retrieve": {
        apiCall: "channels.retrieve(serverID)",
        description: "List channels in the shared server.",
        group: "load",
        protocolPath: "Client.channels.retrieve",
        title: "List channels",
    },
    "Client.channels.retrieveByID": {
        apiCall: "channels.retrieveByID(channelID)",
        description: "Fetch one channel record.",
        group: "load",
        protocolPath: "Client.channels.retrieveByID",
        title: "Channel by ID",
    },
    "Client.channels.userList": {
        apiCall: "channels.userList(channelID)",
        description: "Members visible in the channel.",
        group: "load",
        protocolPath: "Client.channels.userList",
        title: "Channel members",
    },
    "Client.users.familiars": {
        apiCall: "users.familiars()",
        description: "Known contacts / familiars list.",
        group: "load",
        protocolPath: "Client.users.familiars",
        title: "Familiars",
    },
    "Client.users.retrieve": {
        apiCall: "users.retrieve(username)",
        description: "Lookup another user by username.",
        group: "load",
        protocolPath: "Client.users.retrieve",
        title: "User lookup",
    },
    "Client.sessions.retrieve": {
        apiCall: "sessions.retrieve()",
        description: "List active sessions / devices.",
        group: "load",
        protocolPath: "Client.sessions.retrieve",
        title: "Sessions list",
    },
    "Client.me.user; Client.whoami": {
        apiCall: "me.user() + whoami()",
        description: "Profile helper combined with identity refresh.",
        group: "load",
        protocolPath: "Client.me.user; Client.whoami",
        title: "Me · user",
    },
    "Client.me.device; Client.whoami": {
        apiCall: "me.device() + whoami()",
        description: "Device helper combined with identity refresh.",
        group: "load",
        protocolPath: "Client.me.device; Client.whoami",
        title: "Me · device",
    },
    "Client.moderation.fetchPermissionList": {
        apiCall: "moderation.fetchPermissionList(serverID)",
        description: "Moderation permission matrix for the server.",
        group: "load",
        protocolPath: "Client.moderation.fetchPermissionList",
        title: "Mod permissions",
    },
    "Client.invites.retrieve": {
        apiCall: "invites.retrieve(serverID)",
        description: "Outstanding invites on the shared server.",
        group: "load",
        protocolPath: "Client.invites.retrieve",
        title: "List invites",
    },
    "Client.invites.create": {
        apiCall: "invites.create(serverID, duration)",
        description: "Create a new invite while load-testing.",
        group: "load",
        protocolPath: "Client.invites.create",
        title: "Create invite",
    },
    "Client.invites.create; Client.invites.redeem | invite round-trip": {
        apiCall: "invites.create · invites.redeem (round-trip)",
        description: "Hub creates invite, random guest redeems (load path).",
        group: "load",
        protocolPath: "Client.invites.create; Client.invites.redeem",
        title: "Invite round-trip",
    },
    "Client.emoji.retrieveList": {
        apiCall: "emoji.retrieveList(serverID)",
        description: "Custom emoji catalog for the server.",
        group: "load",
        protocolPath: "Client.emoji.retrieveList",
        title: "Emoji list",
    },
    "Client.emoji.create": {
        apiCall: "emoji.create(png, name, serverID)",
        description: "Upload a tiny PNG as custom emoji (hub only).",
        group: "load",
        protocolPath: "Client.emoji.create",
        title: "Emoji upload",
    },
    "Client.files.create": {
        apiCall: "files.create(bytes)",
        description: "Upload small random payload as a file asset.",
        group: "load",
        protocolPath: "Client.files.create",
        title: "File upload",
    },
    "Client.channels.create": {
        apiCall: "channels.create(name, serverID)",
        description: "Create extra channel on shared server (hub only).",
        group: "load",
        protocolPath: "Client.channels.create",
        title: "Channel create",
    },
    "Client.messages.group | chat": {
        apiCall: "messages.group(channelID, body)",
        description: "Group posts in the shared stress-chat guild.",
        group: "load",
        protocolPath: "Client.messages.group",
        title: "Chat · group send",
    },
    "Client.messages.retrieveGroup | chat": {
        apiCall: "messages.retrieveGroup(channelID)",
        description: "Read shared channel history from each client.",
        group: "load",
        protocolPath: "Client.messages.retrieveGroup",
        title: "Chat · group history",
    },
    "Client.messages.send | chat": {
        apiCall: "messages.send(userID, body)",
        description: "DM between two stress users in the same world.",
        group: "load",
        protocolPath: "Client.messages.send",
        title: "Chat · DM send",
    },
    "Client.messages.retrieve | chat": {
        apiCall: "messages.retrieve(userID)",
        description: "DM history fetch with a peer.",
        group: "load",
        protocolPath: "Client.messages.retrieve",
        title: "Chat · DM history",
    },
    "Client.servers.retrieve | chat": {
        apiCall: "servers.retrieve()",
        description: "Guild list while under chat load.",
        group: "load",
        protocolPath: "Client.servers.retrieve",
        title: "Chat · list servers",
    },
    "Client.permissions.retrieve | chat": {
        apiCall: "permissions.retrieve()",
        description: "Permission snapshot during chat scenario.",
        group: "load",
        protocolPath: "Client.permissions.retrieve",
        title: "Chat · permissions",
    },
    "Client.channels.retrieve | chat": {
        apiCall: "channels.retrieve(serverID)",
        description: "Channel listing for the shared server.",
        group: "load",
        protocolPath: "Client.channels.retrieve",
        title: "Chat · list channels",
    },
    "Client.channels.userList | chat": {
        apiCall: "channels.userList(channelID)",
        description: "Member list for #general.",
        group: "load",
        protocolPath: "Client.channels.userList",
        title: "Chat · channel members",
    },
    "Client.servers.retrieveByID | chat": {
        apiCall: "servers.retrieveByID(serverID)",
        description: "Single-server fetch for the stress guild.",
        group: "load",
        protocolPath: "Client.servers.retrieveByID",
        title: "Chat · server by ID",
    },
    "Client.whoami | chat": {
        apiCall: "whoami()",
        description: "Single-client fallback when no DM peer exists.",
        group: "load",
        protocolPath: "Client.whoami",
        title: "Chat · whoami (fallback)",
    },
    "Client.whoami | read": {
        apiCall: "whoami()",
        description: "Light identity checks (whoami scenario).",
        group: "load",
        protocolPath: "Client.whoami",
        title: "Read · whoami",
    },
    "Client.servers.retrieve | read": {
        apiCall: "servers.retrieve()",
        description: "Repeated server listing (servers scenario).",
        group: "load",
        protocolPath: "Client.servers.retrieve",
        title: "Read · servers",
    },
    "Client.permissions.retrieve | read": {
        apiCall: "permissions.retrieve()",
        description: "Mixed scenario: permission reads.",
        group: "load",
        protocolPath: "Client.permissions.retrieve",
        title: "Read · permissions",
    },
};

const NOISE_LOAD_IDS = [
    "grp_msg",
    "grp_hist",
    "dm_send",
    "dm_hist",
    "whoami",
    "srv_list",
    "srv_id",
    "perm_me",
    "ch_list",
    "ch_id",
    "ch_users",
    "fam",
    "usr_get",
    "sess",
    "me_u",
    "me_dev",
    "mod_list",
    "inv_list",
    "inv_mk",
    "inv_flow",
    "emoji_retrieveList",
    "emoji_create",
    "files_create",
    "channels_create",
] as const;

const NOISE_OP_TO_SURFACE: Readonly<Record<string, string>> = {
    grp_msg: "Client.messages.group",
    grp_hist: "Client.messages.retrieveGroup",
    dm_send: "Client.messages.send",
    dm_hist: "Client.messages.retrieve",
    whoami: "Client.whoami",
    srv_list: "Client.servers.retrieve",
    srv_id: "Client.servers.retrieveByID",
    perm_me: "Client.permissions.retrieve",
    ch_list: "Client.channels.retrieve",
    ch_id: "Client.channels.retrieveByID",
    ch_users: "Client.channels.userList",
    fam: "Client.users.familiars",
    usr_get: "Client.users.retrieve",
    sess: "Client.sessions.retrieve",
    me_u: "Client.me.user; Client.whoami",
    me_dev: "Client.me.device; Client.whoami",
    mod_list: "Client.moderation.fetchPermissionList",
    inv_list: "Client.invites.retrieve",
    inv_mk: "Client.invites.create",
    inv_flow:
        "Client.invites.create; Client.invites.redeem | invite round-trip",
    emoji_retrieveList: "Client.emoji.retrieveList",
    emoji_create: "Client.emoji.create",
    files_create: "Client.files.create",
    channels_create: "Client.channels.create",
};

/** Map noise op id (e.g. `inv_mk`) to telemetry `Client.*` surface key. */
export function surfaceKeyForNoiseOpId(opId: string): string {
    return NOISE_OP_TO_SURFACE[opId] ?? `Unknown surface (${opId})`;
}

const BASE_SURFACE_KEYS = [
    "Client.create",
    "Client.register",
    "Client.login",
    "Client.connect",
] as const;

/** Migrate old internal facet ids from issue bundles and logs. */
export const LEGACY_FACET_ID_TO_SURFACE_KEY: Readonly<Record<string, string>> =
    {
        "bootstrap.libvex_create": "Client.create",
        "bootstrap.register": "Client.register",
        "bootstrap.login": "Client.login",
        "bootstrap.ws_connect": "Client.connect",
        "world.noise_server": "Client.servers.create; Client.channels.retrieve",
        "world.noise_invite":
            "Client.invites.create; Client.invites.redeem | world guests",
        "world.noise_ws": "Client.connect | websocket mesh",
        "world.chat_server":
            "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
        "noise.grp_msg": "Client.messages.group",
        "noise.grp_hist": "Client.messages.retrieveGroup",
        "noise.dm_send": "Client.messages.send",
        "noise.dm_hist": "Client.messages.retrieve",
        "noise.whoami": "Client.whoami",
        "noise.srv_list": "Client.servers.retrieve",
        "noise.srv_id": "Client.servers.retrieveByID",
        "noise.perm_me": "Client.permissions.retrieve",
        "noise.ch_list": "Client.channels.retrieve",
        "noise.ch_id": "Client.channels.retrieveByID",
        "noise.ch_users": "Client.channels.userList",
        "noise.fam": "Client.users.familiars",
        "noise.usr_get": "Client.users.retrieve",
        "noise.sess": "Client.sessions.retrieve",
        "noise.me_u": "Client.me.user; Client.whoami",
        "noise.me_dev": "Client.me.device; Client.whoami",
        "noise.mod_list": "Client.moderation.fetchPermissionList",
        "noise.inv_list": "Client.invites.retrieve",
        "noise.inv_mk": "Client.invites.create",
        "noise.inv_flow":
            "Client.invites.create; Client.invites.redeem | invite round-trip",
        "noise.emoji_retrieveList": "Client.emoji.retrieveList",
        "noise.emoji_create": "Client.emoji.create",
        "noise.files_create": "Client.files.create",
        "noise.channels_create": "Client.channels.create",
        "chat.messages_group": "Client.messages.group | chat",
        "chat.messages_retrieveGroup": "Client.messages.retrieveGroup | chat",
        "chat.messages_send_dm": "Client.messages.send | chat",
        "chat.messages_retrieve_dm": "Client.messages.retrieve | chat",
        "chat.servers_retrieve": "Client.servers.retrieve | chat",
        "chat.permissions_retrieve": "Client.permissions.retrieve | chat",
        "chat.channels_retrieve": "Client.channels.retrieve | chat",
        "chat.channels_userList": "Client.channels.userList | chat",
        "chat.servers_retrieveByID": "Client.servers.retrieveByID | chat",
        "chat.whoami_fallback": "Client.whoami | chat",
        "read.whoami": "Client.whoami | read",
        "read.servers_retrieve": "Client.servers.retrieve | read",
        "read.permissions_retrieve": "Client.permissions.retrieve | read",
    };

/** Resolve catalog key from either current `Client.*` keys or legacy internal ids. */
export function normalizeStressSurfaceKey(id: string): string {
    if (STRESS_FACET_CATALOG[id] !== undefined) {
        return id;
    }
    const mapped = LEGACY_FACET_ID_TO_SURFACE_KEY[id];
    return mapped ?? id;
}

/** Canonical `Client.*` path for telemetry / UI (from {@link STRESS_FACET_CATALOG}). */
export function protocolPathForStressFacet(surfaceKey: string): string {
    const key = normalizeStressSurfaceKey(surfaceKey);
    const row = STRESS_FACET_CATALOG[key];
    return row !== undefined ? row.protocolPath : `Unknown (${surfaceKey})`;
}

/** Surface keys registered for a scenario (stable UI ordering). */
export function facetIdsForScenario(scenario: string): readonly string[] {
    const base = [...BASE_SURFACE_KEYS];
    if (scenario === "noise") {
        return [
            ...base,
            "Client.servers.create; Client.channels.retrieve",
            "Client.invites.create; Client.invites.redeem | world guests",
            "Client.connect | websocket mesh",
            ...NOISE_LOAD_IDS.map((id) => surfaceKeyForNoiseOpId(id)),
        ];
    }
    if (scenario === "chat") {
        return [
            ...base,
            "Client.servers.create; Client.channels.retrieve; Client.invites.create; Client.invites.redeem; Client.whoami",
            "Client.messages.group | chat",
            "Client.messages.retrieveGroup | chat",
            "Client.messages.send | chat",
            "Client.messages.retrieve | chat",
            "Client.servers.retrieve | chat",
            "Client.permissions.retrieve | chat",
            "Client.channels.retrieve | chat",
            "Client.channels.userList | chat",
            "Client.servers.retrieveByID | chat",
            "Client.whoami | chat",
        ];
    }
    if (scenario === "whoami") {
        return [...base, "Client.whoami | read"];
    }
    if (scenario === "servers") {
        return [...base, "Client.servers.retrieve | read"];
    }
    return [
        ...base,
        "Client.servers.retrieve | read",
        "Client.permissions.retrieve | read",
    ];
}
