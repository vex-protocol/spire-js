import type { SpireOptions } from "./Spire.ts";

import { Spire } from "./Spire.ts";
import { loadEnv } from "./utils/loadEnv.ts";

function main() {
    // load the environment variables — loadEnv() exits if required vars are missing
    loadEnv();

    const spk = process.env["SPK"];
    if (!spk) {
        throw new Error("SPK must be set (loadEnv should have caught this).");
    }

    const apiPort = process.env["API_PORT"];
    const dbType = parseDbType(process.env["DB_TYPE"]);

    new Spire(spk, {
        ...(apiPort !== undefined ? { apiPort: Number(apiPort) } : {}),
        ...(dbType !== undefined ? { dbType } : {}),
    });
}

function parseDbType(value: string | undefined): SpireOptions["dbType"] {
    switch (value) {
        case "mysql":
        case "sqlite":
        case "sqlite3":
        case "sqlite3mem":
            return value;
        default:
            return undefined;
    }
}

main();
