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
