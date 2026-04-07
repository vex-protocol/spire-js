import { xMakeNonce, XUtils } from "@vex-chat/crypto";
import type {
    IChannel,
    IDevice,
    IDevicePayload,
    IEmoji,
    IFileSQL,
    IInvite,
    IKeyBundle,
    IMailSQL,
    IMailWS,
    IPermission,
    IPreKeysSQL,
    IPreKeysWS,
    IRegistrationPayload,
    IServer,
    IUser,
    IUserRecord,
} from "@vex-chat/types";
import { EventEmitter } from "events";
import { pbkdf2Sync } from "node:crypto";
import * as fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import BetterSqlite3 from "better-sqlite3";
import {
    Kysely,
    Migrator,
    SqliteDialect,
    sql,
    type Migration,
    type MigrationProvider,
} from "kysely";
import * as uuid from "uuid";
import winston from "winston";

import type { ServerDatabase } from "./db/schema.ts";
import type { ISpireOptions } from "./Spire.ts";
import { createLogger } from "./utils/createLogger.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// On Windows, dynamic import() needs file:// URLs, not bare paths like "D:\...".
// pathToFileURL handles this cross-platform.
const migrationFolder = path.join(__dirname, "migrations");

const pubkeyRegex = /[0-9a-f]{64}/;
export const ITERATIONS = 1000;

// ── Row-to-interface converters ─────────────────────────────────────────
// SQLite stores booleans as integers and dates as strings, but the
// @vex-chat/types interfaces expect boolean / Date.

function toUserRecord(row: {
    userID: string;
    username: string;
    passwordHash: string;
    passwordSalt: string;
    lastSeen: string;
}): IUserRecord {
    return { ...row, lastSeen: new Date(row.lastSeen) };
}

function toDevice(row: {
    deviceID: string;
    signKey: string;
    owner: string;
    name: string;
    lastLogin: string;
    deleted: number;
}): IDevice {
    return { ...row, deleted: Boolean(row.deleted) };
}

function toServer(row: {
    serverID: string;
    name: string;
    icon: string | null;
}): IServer {
    return {
        serverID: row.serverID,
        name: row.name,
        icon: row.icon ?? undefined,
    };
}

function toMailSQL(row: {
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
}): IMailSQL {
    return {
        ...row,
        extra: row.extra ?? "",
        time: new Date(row.time),
        forward: Boolean(row.forward),
    };
}

export class Database extends EventEmitter {
    private db: Kysely<ServerDatabase>;
    private log: winston.Logger;

    constructor(options?: ISpireOptions) {
        super();

        this.log = createLogger("spire-db", options?.logLevel || "error");

        const dbType = options?.dbType || "mysql";

        let filename: string;
        switch (dbType) {
            case "sqlite3":
            case "sqlite":
                filename = "spire.sqlite";
                break;
            case "sqlite3mem":
                filename = ":memory:";
                break;
            case "mysql":
            default:
                // For now, fall through to SQLite for mysql too.
                // MySQL dialect can be wired up later with MysqlDialect + mysql2 createPool.
                filename = "spire.sqlite";
                break;
        }

        const sqliteDb = new BetterSqlite3(filename);
        sqliteDb.pragma("journal_mode = WAL");
        sqliteDb.pragma("synchronous = NORMAL");
        sqliteDb.pragma("busy_timeout = 5000");
        sqliteDb.pragma("cache_size = -64000");
        sqliteDb.pragma("temp_store = memory");
        sqliteDb.pragma("foreign_keys = ON");

        this.db = new Kysely<ServerDatabase>({
            dialect: new SqliteDialect({ database: sqliteDb }),
        });

        this.init();
    }

    public async saveOTK(
        userID: string,
        deviceID: string,
        otks: IPreKeysWS[],
    ): Promise<void> {
        for (const otk of otks) {
            const newOTK: IPreKeysSQL = {
                keyID: uuid.v4(),
                userID,
                deviceID: otk.deviceID,
                publicKey: XUtils.encodeHex(otk.publicKey),
                signature: XUtils.encodeHex(otk.signature),
                index: otk.index!,
            };
            await this.db.insertInto("oneTimeKeys").values(newOTK).execute();
        }
    }

    public async getPreKeys(deviceID: string): Promise<IPreKeysWS | null> {
        const rows: IPreKeysSQL[] = await this.db
            .selectFrom("preKeys")
            .selectAll()
            .where("deviceID", "=", deviceID)
            .execute();
        if (rows.length === 0) {
            return null;
        }
        const [preKeyInfo] = rows;
        const preKey: IPreKeysWS = {
            index: preKeyInfo.index,
            publicKey: XUtils.decodeHex(preKeyInfo.publicKey),
            signature: XUtils.decodeHex(preKeyInfo.signature),
            deviceID: preKeyInfo.deviceID,
        };
        return preKey;
    }

    public async retrieveUsers(): Promise<IUserRecord[]> {
        const rows = await this.db.selectFrom("users").selectAll().execute();
        return rows.map(toUserRecord);
    }

    public async getKeyBundle(deviceID: string): Promise<IKeyBundle | null> {
        const device = await this.retrieveDevice(deviceID);
        if (!device) {
            throw new Error("DeviceID not found.");
        }
        const otk = (await this.getOTK(deviceID)) || undefined;
        const preKey = await this.getPreKeys(deviceID);
        if (!preKey) {
            throw new Error("Failed to get prekey.");
        }
        const keyBundle: IKeyBundle = {
            signKey: XUtils.decodeHex(device.signKey),
            preKey,
            otk,
        };
        return keyBundle;
    }

    public async createDevice(
        owner: string,
        payload: IDevicePayload,
    ): Promise<IDevice> {
        const device = {
            owner,
            signKey: payload.signKey,
            deviceID: uuid.v4(),
            name: payload.deviceName,
            lastLogin: new Date(Date.now()).toString(),
            deleted: 0,
        };

        await this.db.insertInto("devices").values(device).execute();

        const medPreKeys: IPreKeysSQL = {
            keyID: uuid.v4(),
            userID: owner,
            deviceID: device.deviceID,
            publicKey: payload.preKey,
            signature: payload.preKeySignature,
            index: payload.preKeyIndex,
        };

        await this.db.insertInto("preKeys").values(medPreKeys).execute();

        return toDevice(device);
    }

    public async deleteDevice(deviceID: string): Promise<void> {
        await this.db
            .deleteFrom("preKeys")
            .where("deviceID", "=", deviceID)
            .execute();

        await this.db
            .deleteFrom("oneTimeKeys")
            .where("deviceID", "=", deviceID)
            .execute();

        await this.db
            .updateTable("devices")
            .set({ deleted: 1 })
            .where("deviceID", "=", deviceID)
            .execute();
    }

    public async retrieveDevice(deviceID: string): Promise<IDevice | null> {
        if (uuid.validate(deviceID)) {
            const rows = await this.db
                .selectFrom("devices")
                .selectAll()
                .where("deviceID", "=", deviceID)
                .where("deleted", "=", 0)
                .execute();

            if (rows.length === 0) {
                return null;
            }
            const [device] = rows;
            return toDevice(device);
        }
        if (pubkeyRegex.test(deviceID)) {
            const rows = await this.db
                .selectFrom("devices")
                .selectAll()
                .where("signKey", "=", deviceID)
                .where("deleted", "=", 0)
                .execute();
            if (rows.length === 0) {
                return null;
            }
            const [device] = rows;
            return toDevice(device);
        }
        return null;
    }

    public async retrieveUserDeviceList(userIDs: string[]): Promise<IDevice[]> {
        const rows = await this.db
            .selectFrom("devices")
            .selectAll()
            .where("owner", "in", userIDs)
            .where("deleted", "=", 0)
            .execute();
        return rows.map(toDevice);
    }

    public async getOTK(deviceID: string): Promise<IPreKeysWS | null> {
        const rows: IPreKeysSQL[] = await this.db
            .selectFrom("oneTimeKeys")
            .selectAll()
            .where("deviceID", "=", deviceID)
            .orderBy("index")
            .limit(1)
            .execute();
        if (rows.length === 0) {
            return null;
        }
        const [otkInfo] = rows;
        const otk: IPreKeysWS = {
            publicKey: XUtils.decodeHex(otkInfo.publicKey),
            signature: XUtils.decodeHex(otkInfo.signature),
            index: otkInfo.index,
            deviceID: otkInfo.deviceID,
        };

        try {
            // delete the otk
            await this.db
                .deleteFrom("oneTimeKeys")
                .where("deviceID", "=", deviceID)
                .where("index", "=", otk.index)
                .execute();
            return otk;
        } catch (err) {
            throw err;
        }
    }

    public async getOTKCount(deviceID: string): Promise<number> {
        const result = await this.db
            .selectFrom("oneTimeKeys")
            .select((eb) => eb.fn.countAll().as("count"))
            .where("deviceID", "=", deviceID)
            .executeTakeFirst();
        return Number(result?.count ?? 0);
    }

    public async createPermission(
        userID: string,
        resourceType: string,
        resourceID: string,
        powerLevel: number,
    ): Promise<IPermission> {
        const permissionID = uuid.v4();

        // check if it already exists
        const checkPermission = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("userID", "=", userID)
            .where("resourceID", "=", resourceID)
            .execute();
        if (checkPermission.length > 0) {
            return checkPermission[0];
        }

        const permission: IPermission = {
            permissionID,
            userID,
            resourceType,
            resourceID,
            powerLevel,
        };

        await this.db.insertInto("permissions").values(permission).execute();
        return permission;
    }

    public async retrieveInvite(inviteID: string): Promise<IInvite | null> {
        const rows = await this.db
            .selectFrom("invites")
            .selectAll()
            .where("inviteID", "=", inviteID)
            .execute();
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async retrieveServerInvites(serverID: string): Promise<IInvite[]> {
        const rows = await this.db
            .selectFrom("invites")
            .selectAll()
            .where("serverID", "=", serverID)
            .execute();

        return rows.filter((invite: IInvite) => {
            const valid =
                new Date(Date.now()).getTime() <
                new Date(invite.expiration).getTime();

            if (!valid) {
                this.deleteInvite(invite.inviteID);
            }

            return valid;
        });
    }

    public async deleteInvite(inviteID: string): Promise<void> {
        await this.db
            .deleteFrom("invites")
            .where("inviteID", "=", inviteID)
            .execute();
    }

    public async createInvite(
        inviteID: string,
        serverID: string,
        ownerID: string,
        expiration: string,
    ): Promise<IInvite> {
        const invite: IInvite = {
            inviteID,
            serverID,
            owner: ownerID,
            expiration,
        };

        await this.db.insertInto("invites").values(invite).execute();
        return invite;
    }

    public async retrieveGroupMembers(
        channelID: string,
    ): Promise<IUserRecord[]> {
        const channel = await this.retrieveChannel(channelID);
        if (!channel) {
            return [];
        }
        const permissions: IPermission[] = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("resourceID", "=", channel.serverID)
            .execute();

        const groupMembers: IUserRecord[] = [];
        for (const permission of permissions) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                groupMembers.push(user);
            }
        }

        return groupMembers;
    }

    public async retrieveChannel(channelID: string): Promise<IChannel | null> {
        const channels: IChannel[] = await this.db
            .selectFrom("channels")
            .selectAll()
            .where("channelID", "=", channelID)
            .limit(1)
            .execute();

        if (channels.length === 0) {
            return null;
        }
        return channels[0];
    }

    public async retrieveChannels(serverID: string): Promise<IChannel[]> {
        const channels: IChannel[] = await this.db
            .selectFrom("channels")
            .selectAll()
            .where("serverID", "=", serverID)
            .execute();
        return channels;
    }

    public async createChannel(
        name: string,
        serverID: string,
    ): Promise<IChannel> {
        const channel: IChannel = {
            channelID: uuid.v4(),
            serverID,
            name,
        };
        await this.db.insertInto("channels").values(channel).execute();
        return channel;
    }

    public async createServer(name: string, ownerID: string): Promise<IServer> {
        // create the server
        const server: IServer = {
            name,
            serverID: uuid.v4(),
        };
        await this.db
            .insertInto("servers")
            .values({
                serverID: server.serverID,
                name: server.name,
                icon: server.icon ?? null,
            })
            .execute();
        // create the admin permission
        await this.createPermission(ownerID, "server", server.serverID, 100);
        // create the general channel
        await this.createChannel("general", server.serverID);
        return server;
    }

    /**
     * Retrives a list of users that should be notified when a specific resourceID
     * experiences changes.
     *
     * @param resourceID
     */
    public async retrieveAffectedUsers(
        resourceID: string,
    ): Promise<IUserRecord[]> {
        const permissionList =
            await this.retrievePermissionsByResourceID(resourceID);

        const users: IUserRecord[] = [];
        for (const permission of permissionList) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                users.push(user);
            }
        }

        return users;
    }

    public async retrievePermissionsByResourceID(
        resourceID: string,
    ): Promise<IPermission[]> {
        return this.db
            .selectFrom("permissions")
            .selectAll()
            .where("resourceID", "=", resourceID)
            .execute();
    }

    public async retrievePermissions(
        userID: string,
        resourceType: string,
    ): Promise<IPermission[]> {
        if (resourceType === "all") {
            const sList = await this.db
                .selectFrom("permissions")
                .selectAll()
                .where("userID", "=", userID)
                .execute();
            return sList;
        }
        const serverList = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("userID", "=", userID)
            .where("resourceType", "=", resourceType)
            .execute();
        return serverList;
    }

    public async retrieveServer(serverID: string): Promise<IServer | null> {
        const rows = await this.db
            .selectFrom("servers")
            .selectAll()
            .where("serverID", "=", serverID)
            .limit(1)
            .execute();
        if (rows.length === 0) {
            return null;
        }
        return toServer(rows[0]);
    }

    public async deletePermissions(resourceID: string): Promise<void> {
        await this.db
            .deleteFrom("permissions")
            .where("resourceID", "=", resourceID)
            .execute();
    }

    public async deletePermission(permissionID: string): Promise<void> {
        await this.db
            .deleteFrom("permissions")
            .where("permissionID", "=", permissionID)
            .execute();
    }

    public async retrievePermission(
        permissionID: string,
    ): Promise<IPermission | null> {
        const rows = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("permissionID", "=", permissionID)
            .execute();

        if (rows.length === 0) {
            return null;
        }

        return rows[0];
    }

    public async deleteChannel(channelID: string): Promise<void> {
        await this.deletePermissions(channelID);
        await this.db
            .deleteFrom("mail")
            .where("group", "=", channelID)
            .execute();
        await this.db
            .deleteFrom("channels")
            .where("channelID", "=", channelID)
            .execute();
    }

    public async createEmoji(emoji: IEmoji): Promise<void> {
        await this.db.insertInto("emojis").values(emoji).execute();
    }

    public async deleteEmoji(emojiID: string): Promise<void> {
        await this.db
            .deleteFrom("emojis")
            .where("emojiID", "=", emojiID)
            .execute();
    }

    public async retrieveEmojiList(userID: string): Promise<IEmoji[]> {
        return this.db
            .selectFrom("emojis")
            .selectAll()
            .where("owner", "=", userID)
            .execute();
    }

    public async retrieveEmoji(emojiID: string): Promise<IEmoji | null> {
        const rows = await this.db
            .selectFrom("emojis")
            .selectAll()
            .where("emojiID", "=", emojiID)
            .execute();
        if (rows.length === 0) {
            return null;
        }
        return rows[0];
    }

    public async deleteServer(serverID: string): Promise<void> {
        await this.deletePermissions(serverID);
        const channels = await this.retrieveChannels(serverID);
        for (const channel of channels) {
            await this.deleteChannel(channel.channelID);
        }
        await this.db
            .deleteFrom("servers")
            .where("serverID", "=", serverID)
            .execute();
    }

    public async retrieveServers(userID: string): Promise<IServer[]> {
        const serverPerms = await this.retrievePermissions(userID, "server");
        if (!serverPerms) {
            return [];
        }
        const serverList: IServer[] = [];
        for (const perm of serverPerms) {
            const server = await this.retrieveServer(perm.resourceID);
            if (server) {
                serverList.push(server);
            }
        }
        return serverList;
    }

    public async createUser(
        regKey: Uint8Array,
        regPayload: IRegistrationPayload,
    ): Promise<[IUserRecord | null, Error | null]> {
        try {
            const salt = xMakeNonce();
            const passwordHash = hashPassword(regPayload.password, salt);

            const user: IUserRecord = {
                userID: uuid.stringify(regKey),
                username: regPayload.username,
                lastSeen: new Date(Date.now()),
                passwordHash: passwordHash.toString("hex"),
                passwordSalt: XUtils.encodeHex(salt),
            };

            await this.db
                .insertInto("users")
                .values({
                    ...user,
                    lastSeen: user.lastSeen.toString(),
                })
                .execute();
            await this.createDevice(user.userID, regPayload);

            return [user, null];
        } catch (err) {
            return [null, err instanceof Error ? err : new Error(String(err))];
        }
    }

    public async createFile(file: IFileSQL): Promise<void> {
        await this.db.insertInto("files").values(file).execute();
    }

    public async retrieveFile(fileID: string): Promise<IFileSQL | null> {
        const file = await this.db
            .selectFrom("files")
            .selectAll()
            .where("fileID", "=", fileID)
            .execute();
        if (file.length === 0) {
            return null;
        }
        return file[0];
    }

    // the identifier can be username, public key, or userID
    public async retrieveUser(
        userIdentifier: string,
    ): Promise<IUserRecord | null> {
        let rows;
        if (uuid.validate(userIdentifier)) {
            rows = await this.db
                .selectFrom("users")
                .selectAll()
                .where("userID", "=", userIdentifier)
                .limit(1)
                .execute();
        } else {
            rows = await this.db
                .selectFrom("users")
                .selectAll()
                .where("username", "=", userIdentifier)
                .limit(1)
                .execute();
        }

        if (rows.length === 0) {
            return null;
        }
        return toUserRecord(rows[0]);
    }

    public async saveMail(
        mail: IMailWS,
        header: Uint8Array,
        deviceID: string,
        userID: string,
    ): Promise<void> {
        const entry: IMailSQL = {
            mailID: mail.mailID,
            mailType: mail.mailType,
            recipient: mail.recipient,
            sender: deviceID,
            cipher: XUtils.encodeHex(mail.cipher),
            nonce: XUtils.encodeHex(mail.nonce),
            extra: XUtils.encodeHex(mail.extra),
            header: XUtils.encodeHex(header),
            time: new Date(Date.now()),
            group: mail.group ? XUtils.encodeHex(mail.group) : null,
            forward: mail.forward,
            authorID: userID,
            readerID: mail.readerID,
        };

        await this.db
            .insertInto("mail")
            .values({
                ...entry,
                time: entry.time.toString(),
                forward: entry.forward ? 1 : 0,
            })
            .execute();
    }

    public async retrieveMail(
        deviceID: string,
        // tslint:disable-next-line: array-type
    ): Promise<[Uint8Array, IMailWS, Date][]> {
        const rawRows = await this.db
            .selectFrom("mail")
            .selectAll()
            .where("recipient", "=", deviceID)
            .execute();
        const rows: IMailSQL[] = rawRows.map(toMailSQL);

        const fixMail: (mail: IMailSQL) => [Uint8Array, IMailWS, Date] = (
            mail,
        ) => {
            const msgb: IMailWS = {
                mailType: mail.mailType,
                mailID: mail.mailID,
                recipient: mail.recipient,
                cipher: XUtils.decodeHex(mail.cipher),
                nonce: XUtils.decodeHex(mail.nonce),
                extra: XUtils.decodeHex(mail.extra),
                sender: mail.sender,
                group: mail.group ? XUtils.decodeHex(mail.group) : null,
                forward: Boolean(mail.forward),
                authorID: mail.authorID,
                readerID: mail.readerID,
            };

            const msgh = XUtils.decodeHex(mail.header);
            return [msgh, msgb, new Date(mail.time)];
        };

        const allMail = rows.map(fixMail);

        return allMail;
    }

    public async deleteMail(nonce: Uint8Array, userID: string): Promise<void> {
        await this.db
            .deleteFrom("mail")
            .where("nonce", "=", XUtils.encodeHex(nonce))
            .where("recipient", "=", userID)
            .execute();
    }

    public async markUserSeen(user: IUserRecord): Promise<void> {
        await this.db
            .updateTable("users")
            .set({ lastSeen: new Date(Date.now()).toString() })
            .where("userID", "=", user.userID)
            .execute();
    }

    public async markDeviceLogin(device: IDevice): Promise<void> {
        await this.db
            .updateTable("devices")
            .set({ lastLogin: new Date(Date.now()).toString() })
            .where("deviceID", "=", device.deviceID)
            .execute();
    }

    public async isHealthy(): Promise<boolean> {
        try {
            await sql`select 1 as ok`.execute(this.db);
            return true;
        } catch (err) {
            this.log.warn("Database health check failed: " + err);
            return false;
        }
    }

    public async getRequestsTotal(): Promise<number> {
        const row = await this.db
            .selectFrom("service_metrics")
            .select("metric_value")
            .where("metric_key", "=", "requests_total")
            .executeTakeFirst();
        const raw = row?.metric_value;
        const count = Number(raw);
        if (!Number.isFinite(count) || count < 0) {
            return 0;
        }
        return count;
    }

    public async incrementRequestsTotal(by = 1): Promise<void> {
        if (!Number.isFinite(by) || by <= 0) {
            return;
        }
        await this.db
            .updateTable("service_metrics")
            .set({
                metric_value: sql`metric_value + ${Math.floor(by)}`,
            })
            .where("metric_key", "=", "requests_total")
            .execute();
    }

    public async close(): Promise<void> {
        this.log.info("Closing database.");
        await this.db.destroy();
    }

    private async init(): Promise<void> {
        // Custom migration provider that uses file:// URLs for dynamic import().
        // FileMigrationProvider uses bare paths which break on Windows (D:\ is
        // not a valid URL scheme for Node's ESM loader).
        const provider: MigrationProvider = {
            async getMigrations(): Promise<Record<string, Migration>> {
                const files = await fs.readdir(migrationFolder);
                const migrations: Record<string, Migration> = {};
                for (const file of files) {
                    if (!file.endsWith(".ts") && !file.endsWith(".js"))
                        continue;
                    const key = file.replace(/\.[tj]s$/, "");
                    const fullPath = path.join(migrationFolder, file);
                    const url = pathToFileURL(fullPath).href;
                    migrations[key] = await import(url);
                }
                return migrations;
            },
        };
        const migrator = new Migrator({
            db: this.db,
            provider,
        });
        const { error } = await migrator.migrateToLatest();
        if (error) {
            this.emit("error", error);
            return;
        }
        this.emit("ready");
    }
}

export const hashPassword = (password: string, salt: Uint8Array) =>
    pbkdf2Sync(password, salt, ITERATIONS, 32, "sha512");
