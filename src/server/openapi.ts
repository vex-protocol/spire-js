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
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

import asyncApiSpec from "@vex-chat/types/asyncapi.json" with { type: "json" };
import openApiSpec from "@vex-chat/types/openapi.json" with { type: "json" };

import { apiReference } from "@scalar/express-api-reference";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env["NODE_ENV"] === "production";

const pkgDir = (pkg: string) =>
    path.resolve(__dirname, "../../node_modules", pkg);

export const setupDocs = (api: express.Application) => {
    // Raw JSON specs — always available (no CSP issues, machine-readable)
    api.get("/openapi.json", (_req, res) => {
        res.json(openApiSpec);
    });
    api.get("/asyncapi.json", (_req, res) => {
        res.json(asyncApiSpec);
    });

    if (isProduction) return;

    // Interactive viewers — development only (require unsafe-eval + CDN)
    api.use("/docs", apiReference({ theme: "purple", url: "/openapi.json" }));
    api.use("/vendor", express.static(pkgDir("@asyncapi/web-component/lib")));
    api.use(
        "/assets",
        express.static(pkgDir("@asyncapi/react-component/styles")),
    );

    api.get("/async-docs", (_req, res) => {
        res.sendFile(path.resolve(__dirname, "../../public/async-docs.html"));
    });
};
