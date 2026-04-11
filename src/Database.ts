import type { ServerDatabase } from "./db/schema.ts";
import type { SpireOptions } from "./Spire.ts";
import type {
    Channel,
    Device,
    DevicePayload,
    Emoji,
    FileSQL,
    Invite,
    KeyBundle,
    MailSQL,
    MailWS,
    Permission,
    PreKeysSQL,
    PreKeysWS,
    RegistrationPayload,
    Server,
    UserRecord,
} from "@vex-chat/types";
import type { Migration, MigrationProvider } from "kysely";
import type winston from "winston";

import { EventEmitter } from "events";
import { pbkdf2Sync } from "node:crypto";
import * as fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { xMakeNonce, XUtils } from "@vex-chat/crypto";
import { MailType } from "@vex-chat/types";

/**
 * Narrow a plain integer from the `mailType` SQL column to the
 * `MailType` union (0 = initial, 1 = subsequent). Throws if the
 * database contains an unexpected value, catching row corruption
 * at read time instead of propagating an invalid literal into
 * application code.
 */
function parseMailType(n: number): MailType {
    if (n === MailType.initial) return MailType.initial;
    if (n === MailType.subsequent) return MailType.subsequent;
    throw new Error(`Invalid mailType in database row: ${String(n)}`);
}

import BetterSqlite3 from "better-sqlite3";
import { Kysely, Migrator, sql, SqliteDialect } from "kysely";
import { stringify as uuidStringify, validate as uuidValidate } from "uuid";

import { createLogger } from "./utils/createLogger.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const migrationFolder = path.join(__dirname, "migrations");

/**
 * Cross-platform Kysely migration provider.
 *
 * Replaces Kysely's built-in `FileMigrationProvider`, which on Windows
 * fails with `ERR_UNSUPPORTED_ESM_URL_SCHEME` because it does
 * `await import(joinedPath)` where `joinedPath` is a Windows absolute
 * path like `D:\\spire\\src\\migrations\\schema.ts`. Node's ESM loader
 * requires `file://` URLs for absolute paths on Windows.
 *
 * This implementation uses `pathToFileURL` to convert each migration
 * file's absolute path to a `file://` URL before passing it to
 * `import()`. Works on Linux, macOS, and Windows. Filters out `.d.ts`
 * declaration files and accepts both `.ts` and `.js` source files for
 * spire's `--experimental-strip-types` runtime.
 */
class CrossPlatformMigrationProvider implements MigrationProvider {
    private readonly folder: string;

    constructor(folder: string) {
        this.folder = folder;
    }

    async getMigrations(): Promise<Record<string, Migration>> {
        const files = await fs.readdir(this.folder);
        const migrations: Record<string, Migration> = {};
        for (const file of files.sort()) {
            if (file.endsWith(".d.ts")) continue;
            if (!file.endsWith(".ts") && !file.endsWith(".js")) continue;
            const fullPath = path.join(this.folder, file);
            const fileUrl = pathToFileURL(fullPath).href;
            const mod: unknown = await import(fileUrl);
            if (!isMigration(mod)) {
                throw new Error(
                    `Invalid migration ${file}: expected an exported \`up\` function`,
                );
            }
            const name = file.replace(/\.(ts|js)$/, "");
            migrations[name] = mod;
        }
        return migrations;
    }
}

function isMigration(mod: unknown): mod is Migration {
    return (
        typeof mod === "object" &&
        mod !== null &&
        "up" in mod &&
        typeof (mod as { up: unknown }).up === "function"
    );
}

const pubkeyRegex = /[0-9a-f]{64}/;
export const ITERATIONS = 1000;

// ── Row-to-interface converters ─────────────────────────────────────────
// SQLite stores booleans as integers and dates as strings, but the
// @vex-chat/types interfaces expect boolean / Date.

export class Database extends EventEmitter {
    private db: Kysely<ServerDatabase>;
    private log: winston.Logger;

    constructor(options?: SpireOptions) {
        super();

        this.log = createLogger("spire-db", options?.logLevel || "error");

        const dbType = options?.dbType || "sqlite3";

        let filename: string;
        switch (dbType) {
            case "sqlite":
            case "sqlite3":
                filename = "spire.sqlite";
                break;
            case "sqlite3mem":
                filename = ":memory:";
                break;
            default:
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

        void this.init();
    }

    public async close(): Promise<void> {
        this.log.info("Closing database.");
        await this.db.destroy();
    }

    public async createChannel(
        name: string,
        serverID: string,
    ): Promise<Channel> {
        const channel: Channel = {
            channelID: crypto.randomUUID(),
            name,
            serverID,
        };
        await this.db.insertInto("channels").values(channel).execute();
        return channel;
    }

    public async createDevice(
        owner: string,
        payload: DevicePayload,
    ): Promise<Device> {
        const device = {
            deleted: 0,
            deviceID: crypto.randomUUID(),
            lastLogin: new Date().toISOString(),
            name: payload.deviceName,
            owner,
            signKey: payload.signKey,
        };

        await this.db.insertInto("devices").values(device).execute();

        const medPreKeys = {
            deviceID: device.deviceID,
            index: payload.preKeyIndex,
            keyID: crypto.randomUUID(),
            publicKey: payload.preKey,
            signature: payload.preKeySignature,
            userID: owner,
        };

        await this.db.insertInto("preKeys").values(medPreKeys).execute();

        return toDevice(device);
    }

    public async createEmoji(emoji: Emoji): Promise<void> {
        await this.db.insertInto("emojis").values(emoji).execute();
    }

    public async createFile(file: FileSQL): Promise<void> {
        await this.db.insertInto("files").values(file).execute();
    }

    public async createInvite(
        inviteID: string,
        serverID: string,
        ownerID: string,
        expiration: string,
    ): Promise<Invite> {
        const invite: Invite = {
            expiration,
            inviteID,
            owner: ownerID,
            serverID,
        };

        await this.db.insertInto("invites").values(invite).execute();
        return invite;
    }

    public async createPermission(
        userID: string,
        resourceType: string,
        resourceID: string,
        powerLevel: number,
    ): Promise<Permission> {
        const permissionID = crypto.randomUUID();

        // check if it already exists
        const checkPermission = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("userID", "=", userID)
            .where("resourceID", "=", resourceID)
            .execute();
        const existing = checkPermission[0];
        if (existing) {
            return existing;
        }

        const permission: Permission = {
            permissionID,
            powerLevel,
            resourceID,
            resourceType,
            userID,
        };

        await this.db.insertInto("permissions").values(permission).execute();
        return permission;
    }

    public async createServer(name: string, ownerID: string): Promise<Server> {
        // create the server
        const server: Server = {
            name,
            serverID: crypto.randomUUID(),
        };
        await this.db
            .insertInto("servers")
            .values({
                icon: server.icon ?? null,
                name: server.name,
                serverID: server.serverID,
            })
            .execute();
        // create the admin permission
        await this.createPermission(ownerID, "server", server.serverID, 100);
        // create the general channel
        await this.createChannel("general", server.serverID);
        return server;
    }

    public async createUser(
        regKey: Uint8Array,
        regPayload: RegistrationPayload,
    ): Promise<[null | UserRecord, Error | null]> {
        try {
            const salt = xMakeNonce();
            const passwordHash = hashPassword(regPayload.password, salt);

            const user: UserRecord = {
                lastSeen: new Date().toISOString(),
                passwordHash: passwordHash.toString("hex"),
                passwordSalt: XUtils.encodeHex(salt),
                userID: uuidStringify(regKey),
                username: regPayload.username,
            };

            await this.db
                .insertInto("users")
                .values({
                    ...user,
                    lastSeen: user.lastSeen,
                })
                .execute();
            await this.createDevice(user.userID, regPayload);

            return [user, null];
        } catch (err: unknown) {
            return [null, err instanceof Error ? err : new Error(String(err))];
        }
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

    public async deleteEmoji(emojiID: string): Promise<void> {
        await this.db
            .deleteFrom("emojis")
            .where("emojiID", "=", emojiID)
            .execute();
    }

    public async deleteInvite(inviteID: string): Promise<void> {
        await this.db
            .deleteFrom("invites")
            .where("inviteID", "=", inviteID)
            .execute();
    }

    public async deleteMail(nonce: Uint8Array, userID: string): Promise<void> {
        await this.db
            .deleteFrom("mail")
            .where("nonce", "=", XUtils.encodeHex(nonce))
            .where("recipient", "=", userID)
            .execute();
    }

    public async deletePermission(permissionID: string): Promise<void> {
        await this.db
            .deleteFrom("permissions")
            .where("permissionID", "=", permissionID)
            .execute();
    }

    public async deletePermissions(resourceID: string): Promise<void> {
        await this.db
            .deleteFrom("permissions")
            .where("resourceID", "=", resourceID)
            .execute();
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

    public async getKeyBundle(deviceID: string): Promise<KeyBundle | null> {
        const device = await this.retrieveDevice(deviceID);
        if (!device) {
            throw new Error("DeviceID not found.");
        }
        const otk = (await this.getOTK(deviceID)) || undefined;
        const preKey = await this.getPreKeys(deviceID);
        if (!preKey) {
            throw new Error("Failed to get prekey.");
        }
        const keyBundle: KeyBundle = {
            otk,
            preKey,
            signKey: XUtils.decodeHex(device.signKey),
        };
        return keyBundle;
    }

    public async getOTK(deviceID: string): Promise<null | PreKeysWS> {
        const rows: PreKeysSQL[] = await this.db
            .selectFrom("oneTimeKeys")
            .selectAll()
            .where("deviceID", "=", deviceID)
            .orderBy("index")
            .limit(1)
            .execute();
        const otkInfo = rows[0];
        if (!otkInfo) {
            return null;
        }
        const otk: PreKeysWS = {
            deviceID: otkInfo.deviceID,
            index: otkInfo.index,
            publicKey: XUtils.decodeHex(otkInfo.publicKey),
            signature: XUtils.decodeHex(otkInfo.signature),
        };

        // delete the otk
        await this.db
            .deleteFrom("oneTimeKeys")
            .where("deviceID", "=", deviceID)
            .where("index", "=", otk.index)
            .execute();
        return otk;
    }

    public async getOTKCount(deviceID: string): Promise<number> {
        const result = await this.db
            .selectFrom("oneTimeKeys")
            .select((eb) => eb.fn.countAll().as("count"))
            .where("deviceID", "=", deviceID)
            .executeTakeFirst();
        return Number(result?.count ?? 0);
    }

    public async getPreKeys(deviceID: string): Promise<null | PreKeysWS> {
        const rows: PreKeysSQL[] = await this.db
            .selectFrom("preKeys")
            .selectAll()
            .where("deviceID", "=", deviceID)
            .execute();
        const preKeyInfo = rows[0];
        if (!preKeyInfo) {
            return null;
        }
        const preKey: PreKeysWS = {
            deviceID: preKeyInfo.deviceID,
            index: preKeyInfo.index,
            publicKey: XUtils.decodeHex(preKeyInfo.publicKey),
            signature: XUtils.decodeHex(preKeyInfo.signature),
        };
        return preKey;
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

    public async isHealthy(): Promise<boolean> {
        try {
            await sql`select 1 as ok`.execute(this.db);
            return true;
        } catch (err: unknown) {
            this.log.warn("Database health check failed: " + String(err));
            return false;
        }
    }

    public async markDeviceLogin(device: Device): Promise<void> {
        await this.db
            .updateTable("devices")
            .set({ lastLogin: new Date().toISOString() })
            .where("deviceID", "=", device.deviceID)
            .execute();
    }

    public async markUserSeen(user: UserRecord): Promise<void> {
        await this.db
            .updateTable("users")
            .set({ lastSeen: new Date().toISOString() })
            .where("userID", "=", user.userID)
            .execute();
    }

    /**
     * Retrives a list of users that should be notified when a specific resourceID
     * experiences changes.
     *
     * @param resourceID
     */
    public async retrieveAffectedUsers(
        resourceID: string,
    ): Promise<UserRecord[]> {
        const permissionList =
            await this.retrievePermissionsByResourceID(resourceID);

        const users: UserRecord[] = [];
        for (const permission of permissionList) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                users.push(user);
            }
        }

        return users;
    }

    public async retrieveChannel(channelID: string): Promise<Channel | null> {
        const channels: Channel[] = await this.db
            .selectFrom("channels")
            .selectAll()
            .where("channelID", "=", channelID)
            .limit(1)
            .execute();

        return channels[0] ?? null;
    }

    public async retrieveChannels(serverID: string): Promise<Channel[]> {
        const channels: Channel[] = await this.db
            .selectFrom("channels")
            .selectAll()
            .where("serverID", "=", serverID)
            .execute();
        return channels;
    }

    public async retrieveDevice(deviceID: string): Promise<Device | null> {
        if (uuidValidate(deviceID)) {
            const rows = await this.db
                .selectFrom("devices")
                .selectAll()
                .where("deviceID", "=", deviceID)
                .where("deleted", "=", 0)
                .execute();

            const device = rows[0];
            return device ? toDevice(device) : null;
        }
        if (pubkeyRegex.test(deviceID)) {
            const rows = await this.db
                .selectFrom("devices")
                .selectAll()
                .where("signKey", "=", deviceID)
                .where("deleted", "=", 0)
                .execute();
            const device = rows[0];
            return device ? toDevice(device) : null;
        }
        return null;
    }

    public async retrieveEmoji(emojiID: string): Promise<Emoji | null> {
        const rows = await this.db
            .selectFrom("emojis")
            .selectAll()
            .where("emojiID", "=", emojiID)
            .execute();
        return rows[0] ?? null;
    }

    public async retrieveEmojiList(userID: string): Promise<Emoji[]> {
        return this.db
            .selectFrom("emojis")
            .selectAll()
            .where("owner", "=", userID)
            .execute();
    }

    public async retrieveFile(fileID: string): Promise<FileSQL | null> {
        const file = await this.db
            .selectFrom("files")
            .selectAll()
            .where("fileID", "=", fileID)
            .execute();
        return file[0] ?? null;
    }

    public async retrieveGroupMembers(
        channelID: string,
    ): Promise<UserRecord[]> {
        const channel = await this.retrieveChannel(channelID);
        if (!channel) {
            return [];
        }
        const permissions: Permission[] = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("resourceID", "=", channel.serverID)
            .execute();

        const groupMembers: UserRecord[] = [];
        for (const permission of permissions) {
            const user = await this.retrieveUser(permission.userID);
            if (user) {
                groupMembers.push(user);
            }
        }

        return groupMembers;
    }

    public async retrieveInvite(inviteID: string): Promise<Invite | null> {
        const rows = await this.db
            .selectFrom("invites")
            .selectAll()
            .where("inviteID", "=", inviteID)
            .execute();
        return rows[0] ?? null;
    }

    public async retrieveMail(
        deviceID: string,
    ): Promise<[Uint8Array, MailWS, string][]> {
        const rawRows = await this.db
            .selectFrom("mail")
            .selectAll()
            .where("recipient", "=", deviceID)
            .execute();
        const rows: MailSQL[] = rawRows.map(toMailSQL);

        const fixMail: (mail: MailSQL) => [Uint8Array, MailWS, string] = (
            mail,
        ) => {
            const msgb: MailWS = {
                authorID: mail.authorID,
                cipher: XUtils.decodeHex(mail.cipher),
                extra: XUtils.decodeHex(mail.extra),
                forward: mail.forward,
                group: mail.group ? XUtils.decodeHex(mail.group) : null,
                mailID: mail.mailID,
                mailType: mail.mailType,
                nonce: XUtils.decodeHex(mail.nonce),
                readerID: mail.readerID,
                recipient: mail.recipient,
                sender: mail.sender,
            };

            const msgh = XUtils.decodeHex(mail.header);
            return [msgh, msgb, mail.time];
        };

        const allMail = rows.map(fixMail);

        return allMail;
    }

    public async retrievePermission(
        permissionID: string,
    ): Promise<null | Permission> {
        const rows = await this.db
            .selectFrom("permissions")
            .selectAll()
            .where("permissionID", "=", permissionID)
            .execute();

        return rows[0] ?? null;
    }

    public async retrievePermissions(
        userID: string,
        resourceType: string,
    ): Promise<Permission[]> {
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

    public async retrievePermissionsByResourceID(
        resourceID: string,
    ): Promise<Permission[]> {
        return this.db
            .selectFrom("permissions")
            .selectAll()
            .where("resourceID", "=", resourceID)
            .execute();
    }

    public async retrieveServer(serverID: string): Promise<null | Server> {
        const rows = await this.db
            .selectFrom("servers")
            .selectAll()
            .where("serverID", "=", serverID)
            .limit(1)
            .execute();
        const row = rows[0];
        return row ? toServer(row) : null;
    }

    public async retrieveServerInvites(serverID: string): Promise<Invite[]> {
        const rows = await this.db
            .selectFrom("invites")
            .selectAll()
            .where("serverID", "=", serverID)
            .execute();

        return rows.filter((invite: Invite) => {
            const valid =
                new Date(Date.now()).getTime() <
                new Date(invite.expiration).getTime();

            if (!valid) {
                void this.deleteInvite(invite.inviteID);
            }

            return valid;
        });
    }

    public async retrieveServers(userID: string): Promise<Server[]> {
        const serverPerms = await this.retrievePermissions(userID, "server");
        const serverList: Server[] = [];
        for (const perm of serverPerms) {
            const server = await this.retrieveServer(perm.resourceID);
            if (server) {
                serverList.push(server);
            }
        }
        return serverList;
    }

    // the identifier can be username, public key, or userID
    public async retrieveUser(
        userIdentifier: string,
    ): Promise<null | UserRecord> {
        let rows;
        if (uuidValidate(userIdentifier)) {
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

        const row = rows[0];
        return row ? toUserRecord(row) : null;
    }

    public async retrieveUserDeviceList(userIDs: string[]): Promise<Device[]> {
        const rows = await this.db
            .selectFrom("devices")
            .selectAll()
            .where("owner", "in", userIDs)
            .where("deleted", "=", 0)
            .execute();
        return rows.map(toDevice);
    }

    public async retrieveUsers(): Promise<UserRecord[]> {
        const rows = await this.db.selectFrom("users").selectAll().execute();
        return rows.map(toUserRecord);
    }

    public async saveMail(
        mail: MailWS,
        header: Uint8Array,
        deviceID: string,
        userID: string,
    ): Promise<void> {
        const entry: MailSQL = {
            authorID: userID,
            cipher: XUtils.encodeHex(mail.cipher),
            extra: XUtils.encodeHex(mail.extra),
            forward: mail.forward,
            group: mail.group ? XUtils.encodeHex(mail.group) : null,
            header: XUtils.encodeHex(header),
            mailID: mail.mailID,
            mailType: mail.mailType,
            nonce: XUtils.encodeHex(mail.nonce),
            readerID: mail.readerID,
            recipient: mail.recipient,
            sender: deviceID,
            time: new Date().toISOString(),
        };

        await this.db
            .insertInto("mail")
            .values({
                ...entry,
                forward: entry.forward ? 1 : 0,
                time: entry.time,
            })
            .execute();
    }

    public async saveOTK(
        userID: string,
        deviceID: string,
        otks: PreKeysWS[],
    ): Promise<void> {
        for (const otk of otks) {
            const newOTK = {
                deviceID: otk.deviceID,
                index: otk.index ?? 0,
                keyID: crypto.randomUUID(),
                publicKey: XUtils.encodeHex(otk.publicKey),
                signature: XUtils.encodeHex(otk.signature),
                userID,
            };
            await this.db.insertInto("oneTimeKeys").values(newOTK).execute();
        }
    }

    private async init(): Promise<void> {
        const migrator = new Migrator({
            db: this.db,
            provider: new CrossPlatformMigrationProvider(migrationFolder),
        });
        const { error } = await migrator.migrateToLatest();
        if (error) {
            this.emit("error", error);
            return;
        }
        this.emit("ready");
    }
}

function toDevice(row: {
    deleted: number;
    deviceID: string;
    lastLogin: string;
    name: string;
    owner: string;
    signKey: string;
}): Device {
    return { ...row, deleted: Boolean(row.deleted) };
}

function toMailSQL(row: {
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
}): MailSQL {
    return {
        ...row,
        extra: row.extra ?? "",
        forward: Boolean(row.forward),
        mailType: parseMailType(row.mailType),
        time: row.time,
    };
}

function toServer(row: {
    icon: null | string;
    name: string;
    serverID: string;
}): Server {
    return {
        icon: row.icon ?? undefined,
        name: row.name,
        serverID: row.serverID,
    };
}

function toUserRecord(row: {
    lastSeen: string;
    passwordHash: string;
    passwordSalt: string;
    userID: string;
    username: string;
}): UserRecord {
    return { ...row };
}

export const hashPassword = (password: string, salt: Uint8Array) =>
    pbkdf2Sync(password, salt, ITERATIONS, 32, "sha512");
