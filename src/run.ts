/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { SpireOptions } from "./Spire.ts";

import { Spire } from "./Spire.ts";
import { loadEnv } from "./utils/loadEnv.ts";

async function main() {
    // load the environment variables — loadEnv() exits if required vars are missing
    loadEnv();

    const spk = process.env["SPK"];
    if (!spk) {
        throw new Error("SPK must be set (loadEnv should have caught this).");
    }

    const rawPort = process.env["API_PORT"]?.trim() ?? "";
    const apiPort =
        rawPort.length > 0 ? Number.parseInt(rawPort, 10) : undefined;
    if (apiPort !== undefined) {
        if (!Number.isFinite(apiPort) || apiPort < 1 || apiPort > 65_535) {
            throw new Error(
                `API_PORT must be 1-65535; got ${JSON.stringify(process.env["API_PORT"])}.`,
            );
        }
    }
    const dbType = parseDbType(process.env["DB_TYPE"]);
    const fips =
        process.env["SPIRE_FIPS"] === "1" ||
        process.env["SPIRE_FIPS"] === "true";

    const options: SpireOptions = {
        ...(apiPort !== undefined ? { apiPort } : {}),
        ...(dbType !== undefined ? { dbType } : {}),
        ...(fips ? { cryptoProfile: "fips" } : {}),
    };

    if (fips) {
        await Spire.createAsync(spk, options);
    } else {
        new Spire(spk, options);
    }
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

void main().catch((err: unknown) => {
    console.error(err);
    process.exit(1);
});
