import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

const routeSources = [
    { file: "src/server/index.ts", prefix: "" },
    { file: "src/server/user.ts", prefix: "/user" },
    { file: "src/server/file.ts", prefix: "/file" },
    { file: "src/server/avatar.ts", prefix: "/avatar" },
    { file: "src/server/invite.ts", prefix: "/invite" },
];

const routeRegex =
    /\b(?:api|router)\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]/g;

const normalizePath = (prefix, routePath) => {
    const combined = `${prefix}/${routePath}`.replace(/\/+/g, "/");
    const openApiPath = combined.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
    if (openApiPath.length > 1 && openApiPath.endsWith("/")) {
        return openApiPath.slice(0, -1);
    }
    return openApiPath;
};

const operationTemplate = (method, openApiPath) => ({
    summary: `${method.toUpperCase()} ${openApiPath}`,
    responses: {
        200: { description: "Success" },
        400: { description: "Bad request" },
        401: { description: "Unauthorized" },
        404: { description: "Not found" },
        500: { description: "Server error" },
    },
});

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
    }
}

const spec = {
    openapi: "3.1.0",
    info: {
        title: "Spire API",
        version: "1.0.0",
        description: "Auto-generated endpoint reference for the Spire Express API.",
    },
    paths,
};

const docsDir = path.join(repoRoot, "docs");
await mkdir(docsDir, { recursive: true });

await writeFile(
    path.join(docsDir, "openapi.json"),
    JSON.stringify(spec, null, 2) + "\n",
    "utf8"
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
    `Generated docs/openapi.json with ${Object.keys(paths).length} route paths.`
);
