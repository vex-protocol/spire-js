import { type Kysely, sql } from "kysely";

export async function down(db: Kysely<unknown>): Promise<void> {
    await db.schema.alterTable("users").dropColumn("hashAlgo").execute();
}

export async function up(db: Kysely<unknown>): Promise<void> {
    await db.schema
        .alterTable("users")
        .addColumn("hashAlgo", "varchar(16)", (cb) =>
            cb.defaultTo("pbkdf2").notNull(),
        )
        .execute();

    await sql`UPDATE users SET hashAlgo = 'pbkdf2' WHERE hashAlgo = 'pbkdf2'`.execute(
        db,
    );
}
