/**
 * API documentation endpoints (development only).
 *
 * - GET /docs        — Scalar OpenAPI viewer (REST API)
 * - GET /async-docs  — AsyncAPI web component viewer (WebSocket protocol)
 * - GET /openapi.json  — raw OpenAPI 3.1 spec
 * - GET /asyncapi.json — raw AsyncAPI 3.0 spec
 *
 * Specs are generated at build time from Zod schemas in @vex-chat/types.
 * The interactive viewers require unsafe-eval (AJV) and CDN scripts (Scalar),
 * so they are disabled in production. Raw JSON specs are always available.
 */
import type express from "express";

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const isProduction = process.env["NODE_ENV"] === "production";

export const setupDocs = (api: express.Application) => {
    const openApiSpec = require("@vex-chat/types/openapi.json") as Record<string, unknown>;
    const asyncApiSpec = require("@vex-chat/types/asyncapi.json") as Record<string, unknown>;

    // Raw JSON specs — always available (no CSP issues, machine-readable)
    api.get("/openapi.json", (_req, res) => { res.json(openApiSpec); });
    api.get("/asyncapi.json", (_req, res) => { res.json(asyncApiSpec); });

    if (isProduction) return;

    // Interactive viewers — development only (require unsafe-eval + CDN)
    const { apiReference } = require("@scalar/express-api-reference") as {
        apiReference: (opts: Record<string, unknown>) => express.RequestHandler;
    };

    api.use("/docs", apiReference({ url: "/openapi.json", theme: "purple" }));

    api.use(
        "/vendor",
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument -- express.static path
        require("express").static(
            path.resolve(__dirname, "../../node_modules/@asyncapi/web-component/lib"),
        ),
    );

    api.get("/async-docs", (_req, res) => {
        res.sendFile(path.resolve(__dirname, "../../public/async-docs.html"));
    });
};
