import { type Kysely, sql } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    const tables = [
        "service_metrics",
        "invites",
        "emojis",
        "files",
        "permissions",
        "channels",
        "servers",
        "oneTimeKeys",
        "preKeys",
        "mail",
        "devices",
        "users",
    ] as const;

    for (const table of tables) {
        await db.schema.dropTable(table).ifExists().execute();
    }
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .createTable("users")
        .ifNotExists()
        .addColumn("userID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("username", "varchar(255)", (cb) => cb.unique())
        .addColumn("passwordHash", "text")
        .addColumn("passwordSalt", "text")
        .addColumn("lastSeen", "text")
        .execute();

    await db.schema
        .createTable("devices")
        .ifNotExists()
        .addColumn("deviceID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("signKey", "varchar(255)", (cb) => cb.unique())
        .addColumn("owner", "varchar(255)")
        .addColumn("name", "varchar(255)")
        .addColumn("lastLogin", "text")
        .addColumn("deleted", "integer", (cb) => cb.defaultTo(0))
        .execute();

    await db.schema
        .createTable("mail")
        .ifNotExists()
        .addColumn("nonce", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("recipient", "varchar(255)")
        .addColumn("mailID", "varchar(255)")
        .addColumn("sender", "varchar(255)")
        .addColumn("header", "text")
        .addColumn("cipher", "text")
        .addColumn("group", "varchar(255)")
        .addColumn("extra", "text")
        .addColumn("mailType", "integer")
        .addColumn("time", "text")
        .addColumn("forward", "integer", (cb) => cb.defaultTo(0))
        .addColumn("authorID", "varchar(255)")
        .addColumn("readerID", "varchar(255)")
        .execute();

    await db.schema
        .createIndex("mail_recipient_idx")
        .ifNotExists()
        .on("mail")
        .column("recipient")
        .execute();

    await db.schema
        .createTable("preKeys")
        .ifNotExists()
        .addColumn("keyID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("userID", "varchar(255)")
        .addColumn("deviceID", "varchar(255)", (cb) => cb.unique())
        .addColumn("publicKey", "text")
        .addColumn("signature", "text")
        .addColumn("index", "integer")
        .execute();

    await db.schema
        .createIndex("preKeys_userID_idx")
        .ifNotExists()
        .on("preKeys")
        .column("userID")
        .execute();

    await db.schema
        .createIndex("preKeys_deviceID_idx")
        .ifNotExists()
        .on("preKeys")
        .column("deviceID")
        .execute();

    await db.schema
        .createTable("oneTimeKeys")
        .ifNotExists()
        .addColumn("keyID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("userID", "varchar(255)")
        .addColumn("deviceID", "varchar(255)")
        .addColumn("publicKey", "text")
        .addColumn("signature", "text")
        .addColumn("index", "integer")
        .execute();

    await db.schema
        .createIndex("oneTimeKeys_userID_idx")
        .ifNotExists()
        .on("oneTimeKeys")
        .column("userID")
        .execute();

    await db.schema
        .createIndex("oneTimeKeys_deviceID_idx")
        .ifNotExists()
        .on("oneTimeKeys")
        .column("deviceID")
        .execute();

    await db.schema
        .createTable("servers")
        .ifNotExists()
        .addColumn("serverID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("name", "varchar(255)")
        .addColumn("icon", "varchar(255)")
        .execute();

    await db.schema
        .createTable("channels")
        .ifNotExists()
        .addColumn("channelID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("serverID", "varchar(255)")
        .addColumn("name", "varchar(255)")
        .execute();

    await db.schema
        .createTable("permissions")
        .ifNotExists()
        .addColumn("permissionID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("userID", "varchar(255)")
        .addColumn("resourceType", "varchar(255)")
        .addColumn("resourceID", "varchar(255)")
        .addColumn("powerLevel", "integer")
        .execute();

    await db.schema
        .createIndex("permissions_userID_idx")
        .ifNotExists()
        .on("permissions")
        .column("userID")
        .execute();

    await db.schema
        .createIndex("permissions_resourceID_idx")
        .ifNotExists()
        .on("permissions")
        .column("resourceID")
        .execute();

    await db.schema
        .createTable("files")
        .ifNotExists()
        .addColumn("fileID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("owner", "varchar(255)")
        .addColumn("nonce", "varchar(255)")
        .execute();

    await db.schema
        .createIndex("files_owner_idx")
        .ifNotExists()
        .on("files")
        .column("owner")
        .execute();

    await db.schema
        .createTable("emojis")
        .ifNotExists()
        .addColumn("emojiID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("owner", "varchar(255)")
        .addColumn("name", "varchar(255)")
        .execute();

    await db.schema
        .createIndex("emojis_owner_idx")
        .ifNotExists()
        .on("emojis")
        .column("owner")
        .execute();

    await db.schema
        .createTable("invites")
        .ifNotExists()
        .addColumn("inviteID", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("serverID", "varchar(255)")
        .addColumn("owner", "varchar(255)")
        .addColumn("expiration", "text")
        .execute();

    await db.schema
        .createIndex("invites_serverID_idx")
        .ifNotExists()
        .on("invites")
        .column("serverID")
        .execute();

    await db.schema
        .createTable("service_metrics")
        .ifNotExists()
        .addColumn("metric_key", "varchar(255)", (cb) => cb.primaryKey())
        .addColumn("metric_value", "bigint", (cb) => cb.notNull().defaultTo(0))
        .execute();

    // Seed the requests_total metric row
    await sql`INSERT OR IGNORE INTO service_metrics (metric_key, metric_value) VALUES ('requests_total', 0)`.execute(
        db,
    );
}
