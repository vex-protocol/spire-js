/**
 * API documentation endpoints.
 *
 * - GET /docs      — Scalar OpenAPI viewer (REST API)
 * - GET /async-docs — AsyncAPI web component viewer (WebSocket protocol)
 * - GET /openapi.json  — raw OpenAPI 3.1 spec
 * - GET /asyncapi.json — raw AsyncAPI 3.0 spec
 *
 * Specs are generated at build time from Zod schemas in @vex-chat/types.
 */
import type express from "express";

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { apiReference } from "@scalar/express-api-reference";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const setupDocs = (api: express.Application) => {
    const openApiSpec = require("@vex-chat/types/openapi.json") as Record<string, unknown>;
    const asyncApiSpec = require("@vex-chat/types/asyncapi.json") as Record<string, unknown>;

    // Raw JSON specs
    api.get("/openapi.json", (_req, res) => { res.json(openApiSpec); });
    api.get("/asyncapi.json", (_req, res) => { res.json(asyncApiSpec); });

    // Scalar — OpenAPI viewer
    api.use("/docs", apiReference({ content: openApiSpec, theme: "purple" }));

    // Self-host the AsyncAPI web component JS from node_modules
    api.use(
        "/vendor",
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument -- express.static path
        require("express").static(
            path.resolve(__dirname, "../../node_modules/@asyncapi/web-component/lib"),
        ),
    );

    // AsyncAPI viewer — static HTML page
    api.get("/async-docs", (_req, res) => {
        res.sendFile(path.resolve(__dirname, "../../public/async-docs.html"));
    });
};
