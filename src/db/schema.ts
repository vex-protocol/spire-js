import type { Insertable, Selectable, Updateable } from "kysely";

// ── Table interfaces ────────────────────────────────────────────────────

export type ChannelRow = Selectable<ChannelsTable>;

export interface ChannelsTable {
    channelID: string;
    name: string;
    serverID: string;
}

export type ChannelUpdate = Updateable<ChannelsTable>;

export type DeviceRow = Selectable<DevicesTable>;

export interface DevicesTable {
    deleted: number;
    deviceID: string;
    lastLogin: string;
    name: string;
    owner: string;
    signKey: string;
}

export type DeviceUpdate = Updateable<DevicesTable>;

export type EmojiRow = Selectable<EmojisTable>;

export interface EmojisTable {
    emojiID: string;
    name: string;
    owner: string;
}

export type EmojiUpdate = Updateable<EmojisTable>;

export type FileRow = Selectable<FilesTable>;

export interface FilesTable {
    fileID: string;
    nonce: string;
    owner: string;
}

export type FileUpdate = Updateable<FilesTable>;

// ── Database schema ─────────────────────────────────────────────────────

export type InviteRow = Selectable<InvitesTable>;

// ── Row utility types ───────────────────────────────────────────────────

export interface InvitesTable {
    expiration: string;
    inviteID: string;
    owner: string;
    serverID: string;
}
export type InviteUpdate = Updateable<InvitesTable>;
export type MailRow = Selectable<MailTable>;

export interface MailTable {
    authorID: string;
    cipher: string;
    extra: null | string;
    forward: number;
    group: null | string;
    header: string;
    mailID: string;
    mailType: number;
    nonce: string;
    readerID: string;
    recipient: string;
    sender: string;
    time: string;
}
export type MailUpdate = Updateable<MailTable>;
export type NewChannel = Insertable<ChannelsTable>;

export type NewDevice = Insertable<DevicesTable>;
export type NewEmoji = Insertable<EmojisTable>;
export type NewFile = Insertable<FilesTable>;

export type NewInvite = Insertable<InvitesTable>;
export type NewMail = Insertable<MailTable>;
export type NewOneTimeKey = Insertable<OneTimeKeysTable>;

export type NewPermission = Insertable<PermissionsTable>;
export type NewPreKey = Insertable<PreKeysTable>;
export type NewServer = Insertable<ServersTable>;

export type NewServiceMetric = Insertable<ServiceMetricsTable>;
export type NewUser = Insertable<UsersTable>;
export type OneTimeKeyRow = Selectable<OneTimeKeysTable>;

export interface OneTimeKeysTable {
    deviceID: string;
    index: number;
    keyID: string;
    publicKey: string;
    signature: string;
    userID: string;
}
export type OneTimeKeyUpdate = Updateable<OneTimeKeysTable>;
export type PermissionRow = Selectable<PermissionsTable>;

export interface PermissionsTable {
    permissionID: string;
    powerLevel: number;
    resourceID: string;
    resourceType: string;
    userID: string;
}
export type PermissionUpdate = Updateable<PermissionsTable>;
export type PreKeyRow = Selectable<PreKeysTable>;

export interface PreKeysTable {
    deviceID: string;
    index: number;
    keyID: string;
    publicKey: string;
    signature: string;
    userID: string;
}
export type PreKeyUpdate = Updateable<PreKeysTable>;
export interface ServerDatabase {
    channels: ChannelsTable;
    devices: DevicesTable;
    emojis: EmojisTable;
    files: FilesTable;
    invites: InvitesTable;
    mail: MailTable;
    oneTimeKeys: OneTimeKeysTable;
    permissions: PermissionsTable;
    preKeys: PreKeysTable;
    servers: ServersTable;
    service_metrics: ServiceMetricsTable;
    users: UsersTable;
}

export type ServerRow = Selectable<ServersTable>;
export interface ServersTable {
    icon: null | string;
    name: string;
    serverID: string;
}
export type ServerUpdate = Updateable<ServersTable>;

export type ServiceMetricRow = Selectable<ServiceMetricsTable>;
export interface ServiceMetricsTable {
    metric_key: string;
    metric_value: number;
}
export type ServiceMetricUpdate = Updateable<ServiceMetricsTable>;

export type UserRow = Selectable<UsersTable>;
export interface UsersTable {
    lastSeen: string;
    passwordHash: string;
    passwordSalt: string;
    userID: string;
    username: string;
}
export type UserUpdate = Updateable<UsersTable>;
