/**
 * Serves the OpenAPI and AsyncAPI specs from @vex-chat/types.
 *
 * The specs are generated at build time from Zod schemas (the single source
 * of truth) — not introspected from Express routes at runtime.
 * See types-js/scripts/generate-openapi.ts and generate-asyncapi.ts.
 */
import type express from "express";

import { createRequire } from "node:module";

import swaggerUi from "swagger-ui-express";

const require = createRequire(import.meta.url);

export const setupOpenApiDocs = (api: express.Application) => {
    // Load the pre-generated specs from @vex-chat/types
    const openApiSpec = require("@vex-chat/types/openapi.json") as Record<
        string,
        unknown
    >;
    const asyncApiSpec = require("@vex-chat/types/asyncapi.json") as Record<
        string,
        unknown
    >;

    // Serve raw JSON specs
    api.get("/docs/openapi.json", (_req, res) => {
        res.json(openApiSpec);
    });

    api.get("/docs/asyncapi.json", (_req, res) => {
        res.json(asyncApiSpec);
    });

    // Swagger UI for REST API
    api.use(
        "/docs",
        swaggerUi.serve,
        swaggerUi.setup(openApiSpec as swaggerUi.JsonObject),
    );
};
