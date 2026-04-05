import { Spire } from "./Spire.js";
import { loadEnv } from "./utils/loadEnv.js";

async function main() {
    // load the environment variables
    loadEnv();
    const server = new Spire(process.env.SPK!, {
        apiPort: Number(process.env.API_PORT!),
        dbType: process.env.DB_TYPE as any,
        logLevel: "info",
    });
}

main();
