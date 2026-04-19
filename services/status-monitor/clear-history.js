/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import Database from "better-sqlite3";

const DEFAULT_DB_PATH =
    process.env.STATUS_DB_PATH || "./monitoring/status-history.sqlite";

function parseArgs(argv) {
    const args = {
        dbPath: DEFAULT_DB_PATH,
        yes: false,
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--db" && argv[i + 1]) {
            args.dbPath = argv[i + 1];
            i += 1;
            continue;
        }
        if (arg === "--yes" || arg === "-y") {
            args.yes = true;
        }
    }

    return args;
}

function main() {
    const { dbPath, yes } = parseArgs(process.argv.slice(2));
    if (!yes) {
        console.error(
            "Refusing to clear history without confirmation. Re-run with --yes.",
        );
        process.exit(1);
    }

    const db = new Database(dbPath);
    db.pragma("busy_timeout = 5000");

    const beforeRow = db
        .prepare("SELECT COUNT(*) AS count FROM status_samples")
        .get();
    const beforeCount = Number(beforeRow?.count || 0);

    const tx = db.transaction(() => {
        db.prepare("DELETE FROM status_samples").run();
        db.prepare("DELETE FROM sqlite_sequence WHERE name = ?").run(
            "status_samples",
        );
    });
    tx();

    db.pragma("wal_checkpoint(TRUNCATE)");
    db.exec("VACUUM");
    db.close();

    console.log(`Cleared ${beforeCount} status sample(s) from ${dbPath}`);
}

main();
