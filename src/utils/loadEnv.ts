/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { config } from "dotenv";

/* Populate process.env with vars from .env and verify required vars are present. */
export function loadEnv(): void {
    config();
    const requiredEnvVars: string[] = ["DB_TYPE", "JWT_SECRET", "SPK"];
    for (const required of requiredEnvVars) {
        if (process.env[required] === undefined) {
            process.stderr.write(
                `Required environment variable '${required}' is not set. Please consult the README.\n`,
            );
            process.exit(1);
        }
    }
}
