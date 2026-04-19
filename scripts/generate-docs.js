/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

const routeSources = [
    { file: "src/Spire.ts", prefix: "" },
    { file: "src/server/index.ts", prefix: "" },
    { file: "src/server/user.ts", prefix: "/user" },
    { file: "src/server/file.ts", prefix: "/file" },
    { file: "src/server/avatar.ts", prefix: "/avatar" },
    { file: "src/server/invite.ts", prefix: "/invite" },
];

const routeRegex =
    /\b(?:api|router|this\.api)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/g;

const normalizePath = (prefix, routePath) => {
    const combined = `${prefix}/${routePath}`.replace(/\/+/g, "/");
    const openApiPath = combined.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
    if (openApiPath.length > 1 && openApiPath.endsWith("/")) {
        return openApiPath.slice(0, -1);
    }
    return openApiPath;
};

const extractPathParameters = (openApiPath) => {
    const matches = [...openApiPath.matchAll(/\{([A-Za-z0-9_]+)\}/g)];
    return matches.map((match) => ({
        name: match[1],
        in: "path",
        required: true,
        schema: {
            type: "string",
        },
    }));
};

const operationTemplate = (method, openApiPath) => {
    const parameters = extractPathParameters(openApiPath);
    const hasRequestBody = ["post", "put", "patch"].includes(
        method.toLowerCase(),
    );
    return {
        summary: `${method.toUpperCase()} ${openApiPath}`,
        ...(parameters.length > 0 ? { parameters } : {}),
        ...(hasRequestBody
            ? {
                  requestBody: {
                      required: true,
                      content: {
                          "application/json": {
                              schema: {
                                  type: "object",
                                  additionalProperties: true,
                              },
                          },
                          "application/msgpack": {
                              schema: {
                                  type: "object",
                                  additionalProperties: true,
                              },
                          },
                      },
                  },
              }
            : {}),
        responses: {
            200: { description: "Success" },
            400: { description: "Bad request" },
            401: { description: "Unauthorized" },
            404: { description: "Not found" },
            500: { description: "Server error" },
        },
    };
};

const endpointOverrides = {
    "get /token/{tokenType}": {
        summary: "Create one-time action token",
        description:
            "Returns a short-lived action token keyed by `tokenType`. Tokens expire after about 10 minutes (`TOKEN_EXPIRY`) and are one-time use.\n\nCurrently validated in this codebase by:\n- `register` -> `POST /register`\n- `device` -> `POST /user/:id/devices`\n- `connect` -> `POST /device/:id/connect`\n\nThe endpoint also accepts `file`, `avatar`, `invite`, and `emoji`, which are available scopes but are not explicitly validated by a route in this repository at the moment.\n\nAuth behavior:\n- `tokenType=register` is public.\n- All other token types require a valid `auth` cookie.\n\nHow to fetch:\n1. Authenticate first with `POST /auth` to obtain `auth` cookie (except `register`).\n2. Call `GET /token/{tokenType}`.\n3. Use returned token key in the matching flow promptly.",
        parameters: [
            {
                name: "tokenType",
                in: "path",
                required: true,
                description:
                    "Requested token scope. Allowed values map to server token scopes.",
                schema: {
                    type: "string",
                    enum: [
                        "file",
                        "register",
                        "avatar",
                        "device",
                        "invite",
                        "emoji",
                        "connect",
                    ],
                },
                examples: {
                    register: {
                        summary: "Public registration token",
                        value: "register",
                    },
                    device: {
                        summary: "Authenticated device enrollment token",
                        value: "device",
                    },
                },
            },
        ],
        responses: {
            200: {
                description:
                    "Token created. Response format follows `Accept` header (`application/msgpack` by default, or `application/json`).",
                content: {
                    "application/json": {
                        schema: {
                            type: "object",
                            properties: {
                                key: { type: "string" },
                                time: { type: "string", format: "date-time" },
                                scope: { type: "string" },
                            },
                            required: ["key", "time", "scope"],
                        },
                    },
                    "application/msgpack": {
                        schema: {
                            type: "object",
                            properties: {
                                key: { type: "string" },
                                time: { type: "string", format: "date-time" },
                                scope: { type: "string" },
                            },
                            required: ["key", "time", "scope"],
                        },
                    },
                },
            },
            400: {
                description: "Invalid tokenType supplied.",
            },
            401: {
                description:
                    "Authentication required for non-register token types.",
            },
            500: {
                description: "Unexpected server error while creating token.",
            },
        },
    },
    "get /healthz": {
        summary: "Liveness and readiness probe",
        description:
            "Lightweight probe endpoint for uptime checks. Returns 200 when database initialization has completed, otherwise 503 while booting.",
        responses: {
            200: {
                description: "Service is healthy enough to receive traffic.",
                content: {
                    "application/json": {
                        schema: {
                            type: "object",
                            properties: {
                                ok: { type: "boolean" },
                                dbReady: { type: "boolean" },
                            },
                            required: ["ok", "dbReady"],
                        },
                    },
                },
            },
            503: {
                description: "Service is alive but not ready yet.",
                content: {
                    "application/json": {
                        schema: {
                            type: "object",
                            properties: {
                                ok: { type: "boolean" },
                                dbReady: { type: "boolean" },
                            },
                            required: ["ok", "dbReady"],
                        },
                    },
                },
            },
        },
    },
    "get /status": {
        summary: "Detailed runtime status",
        description:
            "Operational status endpoint including uptime, build metadata, health-check timing, basic runtime counters, and boolean `canary` from env `CANARY`.",
        responses: {
            200: {
                description: "Detailed status payload.",
                content: {
                    "application/json": {
                        schema: {
                            type: "object",
                            properties: {
                                canary: { type: "boolean" },
                                ok: { type: "boolean" },
                                uptimeSeconds: { type: "integer" },
                                startedAt: {
                                    type: "string",
                                    format: "date-time",
                                },
                                now: { type: "string", format: "date-time" },
                                version: { type: "string" },
                                commitSha: { type: "string" },
                                checkDurationMs: { type: "integer" },
                                latencyBudgetMs: { type: "integer" },
                                withinLatencyBudget: { type: "boolean" },
                                metrics: {
                                    type: "object",
                                    properties: {
                                        requestsTotal: { type: "integer" },
                                    },
                                    required: ["requestsTotal"],
                                },
                                dbReady: { type: "boolean" },
                                dbHealthy: { type: "boolean" },
                            },
                            required: [
                                "canary",
                                "ok",
                                "uptimeSeconds",
                                "startedAt",
                                "now",
                                "version",
                                "commitSha",
                                "checkDurationMs",
                                "latencyBudgetMs",
                                "withinLatencyBudget",
                                "metrics",
                                "dbReady",
                                "dbHealthy",
                            ],
                        },
                    },
                },
            },
        },
    },
};

const paths = {};

for (const { file, prefix } of routeSources) {
    const absoluteFile = path.join(repoRoot, file);
    const source = await readFile(absoluteFile, "utf8");

    let match;
    while ((match = routeRegex.exec(source)) !== null) {
        const method = match[1].toLowerCase();
        const routePath = match[2];
        const openApiPath = normalizePath(prefix, routePath);

        if (!paths[openApiPath]) {
            paths[openApiPath] = {};
        }

        if (!paths[openApiPath][method]) {
            paths[openApiPath][method] = operationTemplate(method, openApiPath);
        }

        const overrideKey = `${method} ${openApiPath}`;
        if (endpointOverrides[overrideKey]) {
            paths[openApiPath][method] = {
                ...paths[openApiPath][method],
                ...endpointOverrides[overrideKey],
            };
        }
    }
}

const spec = {
    openapi: "3.1.0",
    info: {
        title: "Spire API",
        version: "1.0.0",
        description:
            "Auto-generated endpoint reference for the Spire Express API.",
    },
    servers: [
        {
            url: "https://api.vex.wtf",
        },
    ],
    paths,
};

const docsDir = path.join(repoRoot, "docs");
await mkdir(docsDir, { recursive: true });

await writeFile(
    path.join(docsDir, "openapi.json"),
    JSON.stringify(spec, null, 2) + "\n",
    "utf8",
);

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Spire API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: "./openapi.json",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis],
    });
  </script>
</body>
</html>
`;

await writeFile(path.join(docsDir, "index.html"), html, "utf8");

console.log(
    `Generated docs/openapi.json with ${Object.keys(paths).length} route paths.`,
);
