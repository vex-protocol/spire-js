/**
 * PM2 process definitions for Spire and sidecar services.
 *
 * Start all: `pm2 start ecosystem.config.cjs`
 * Start only the API: `pm2 start ecosystem.config.cjs --only spire`
 *
 * Deploy hook requires DEPLOY_HOOK_SECRET in the environment (do not commit it).
 * Example: `DEPLOY_HOOK_SECRET='...' pm2 start ecosystem.config.cjs --only deploy-hook`
 */
const path = require("node:path");

const root = __dirname;

module.exports = {
    apps: [
        {
            name: "spire",
            cwd: root,
            script: "src/run.ts",
            interpreter: "node",
            instances: 1,
            autorestart: true,
            watch: false,
            max_memory_restart: "1G",
            env: {
                NODE_ENV: "production",
            },
        },
        {
            name: "deploy-hook",
            cwd: root,
            script: "services/deploy-hook/index.js",
            interpreter: "node",
            instances: 1,
            autorestart: true,
            watch: false,
            env: {
                DEPLOY_REPO_ROOT: root,
            },
        },
    ],
};
