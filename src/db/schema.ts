import type { Insertable, Selectable, Updateable } from "kysely";

// ── Table interfaces ────────────────────────────────────────────────────

export interface UsersTable {
    userID: string;
    username: string;
    passwordHash: string;
    passwordSalt: string;
    lastSeen: string;
}

export interface DevicesTable {
    deviceID: string;
    signKey: string;
    owner: string;
    name: string;
    lastLogin: string;
    deleted: number;
}

export interface MailTable {
    nonce: string;
    recipient: string;
    mailID: string;
    sender: string;
    header: string;
    cipher: string;
    group: string | null;
    extra: string | null;
    mailType: number;
    time: string;
    forward: number;
    authorID: string;
    readerID: string;
}

export interface PreKeysTable {
    keyID: string;
    userID: string;
    deviceID: string;
    publicKey: string;
    signature: string;
    index: number;
}

export interface OneTimeKeysTable {
    keyID: string;
    userID: string;
    deviceID: string;
    publicKey: string;
    signature: string;
    index: number;
}

export interface ServersTable {
    serverID: string;
    name: string;
    icon: string | null;
}

export interface ChannelsTable {
    channelID: string;
    serverID: string;
    name: string;
}

export interface PermissionsTable {
    permissionID: string;
    userID: string;
    resourceType: string;
    resourceID: string;
    powerLevel: number;
}

export interface FilesTable {
    fileID: string;
    owner: string;
    nonce: string;
}

export interface EmojisTable {
    emojiID: string;
    owner: string;
    name: string;
}

export interface InvitesTable {
    inviteID: string;
    serverID: string;
    owner: string;
    expiration: string;
}

export interface ServiceMetricsTable {
    metric_key: string;
    metric_value: number;
}

// ── Database schema ─────────────────────────────────────────────────────

export interface ServerDatabase {
    users: UsersTable;
    devices: DevicesTable;
    mail: MailTable;
    preKeys: PreKeysTable;
    oneTimeKeys: OneTimeKeysTable;
    servers: ServersTable;
    channels: ChannelsTable;
    permissions: PermissionsTable;
    files: FilesTable;
    emojis: EmojisTable;
    invites: InvitesTable;
    service_metrics: ServiceMetricsTable;
}

// ── Row utility types ───────────────────────────────────────────────────

export type UserRow = Selectable<UsersTable>;
export type NewUser = Insertable<UsersTable>;
export type UserUpdate = Updateable<UsersTable>;

export type DeviceRow = Selectable<DevicesTable>;
export type NewDevice = Insertable<DevicesTable>;
export type DeviceUpdate = Updateable<DevicesTable>;

export type MailRow = Selectable<MailTable>;
export type NewMail = Insertable<MailTable>;
export type MailUpdate = Updateable<MailTable>;

export type PreKeyRow = Selectable<PreKeysTable>;
export type NewPreKey = Insertable<PreKeysTable>;
export type PreKeyUpdate = Updateable<PreKeysTable>;

export type OneTimeKeyRow = Selectable<OneTimeKeysTable>;
export type NewOneTimeKey = Insertable<OneTimeKeysTable>;
export type OneTimeKeyUpdate = Updateable<OneTimeKeysTable>;

export type ServerRow = Selectable<ServersTable>;
export type NewServer = Insertable<ServersTable>;
export type ServerUpdate = Updateable<ServersTable>;

export type ChannelRow = Selectable<ChannelsTable>;
export type NewChannel = Insertable<ChannelsTable>;
export type ChannelUpdate = Updateable<ChannelsTable>;

export type PermissionRow = Selectable<PermissionsTable>;
export type NewPermission = Insertable<PermissionsTable>;
export type PermissionUpdate = Updateable<PermissionsTable>;

export type FileRow = Selectable<FilesTable>;
export type NewFile = Insertable<FilesTable>;
export type FileUpdate = Updateable<FilesTable>;

export type EmojiRow = Selectable<EmojisTable>;
export type NewEmoji = Insertable<EmojisTable>;
export type EmojiUpdate = Updateable<EmojisTable>;

export type InviteRow = Selectable<InvitesTable>;
export type NewInvite = Insertable<InvitesTable>;
export type InviteUpdate = Updateable<InvitesTable>;

export type ServiceMetricRow = Selectable<ServiceMetricsTable>;
export type NewServiceMetric = Insertable<ServiceMetricsTable>;
export type ServiceMetricUpdate = Updateable<ServiceMetricsTable>;
