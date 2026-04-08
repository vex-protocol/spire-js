import type express from "express";

import swaggerUi from "swagger-ui-express";

type AnyApp = express.Application & { _router?: { stack?: any[] } };
type AnyRouter = express.Router & { stack?: any[] };

interface IOpenApiOperation {
    responses: Record<string, { description: string }>;
    summary: string;
}

interface IOpenApiSpec {
    info: {
        description: string;
        title: string;
        version: string;
    };
    openapi: string;
    paths: Record<string, Record<string, IOpenApiOperation>>;
}

interface IRouterMount {
    basePath: string;
    router: AnyRouter;
}

const normalizePath = (prefix: string, pathValue: string) => {
    const combined = `${prefix}/${pathValue}`.replace(/\/+/g, "/");
    const withParams = combined.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
    return withParams.endsWith("/") && withParams.length > 1
        ? withParams.slice(0, -1)
        : withParams;
};

const addOperation = (
    paths: IOpenApiSpec["paths"],
    method: string,
    openApiPath: string,
) => {
    const key = method.toLowerCase();
    if (!paths[openApiPath]) {
        paths[openApiPath] = {};
    }
    paths[openApiPath][key] = {
        responses: {
            "200": { description: "Success" },
            "400": { description: "Bad request" },
            "401": { description: "Unauthorized" },
            "404": { description: "Not found" },
            "500": { description: "Server error" },
        },
        summary: `${method.toUpperCase()} ${openApiPath}`,
    };
};

const collectFromStack = (
    stack: any[],
    paths: IOpenApiSpec["paths"],
    prefix = "",
) => {
    for (const layer of stack) {
        if (layer?.route?.path && layer?.route?.methods) {
            const routePath = layer.route.path as string;
            const openApiPath = normalizePath(prefix, routePath);
            const methods = Object.keys(layer.route.methods);
            for (const method of methods) {
                addOperation(paths, method, openApiPath);
            }
            continue;
        }

        if (layer?.handle?.stack && Array.isArray(layer.handle.stack)) {
            collectFromStack(layer.handle.stack, paths, prefix);
        }
    }
};

const createOpenApiSpec = (
    api: AnyApp,
    mountedRouters: IRouterMount[],
): IOpenApiSpec => {
    const paths: IOpenApiSpec["paths"] = {};

    if (api._router?.stack && Array.isArray(api._router.stack)) {
        collectFromStack(api._router.stack, paths);
    }

    for (const { basePath, router } of mountedRouters) {
        if (router.stack && Array.isArray(router.stack)) {
            collectFromStack(router.stack, paths, basePath);
        }
    }

    return {
        info: {
            description:
                "Auto-generated endpoint reference for the Spire Express API.",
            title: "Spire API",
            version: "1.0.0",
        },
        openapi: "3.1.0",
        paths,
    };
};

export const setupOpenApiDocs = (
    api: express.Application,
    mountedRouters: IRouterMount[],
) => {
    const app = api as AnyApp;

    app.get("/docs.json", (_req, res) => {
        res.json(createOpenApiSpec(app, mountedRouters));
    });

    app.use(
        "/docs",
        swaggerUi.serve,
        swaggerUi.setup(undefined, {
            swaggerOptions: {
                url: "/docs.json",
            },
        }),
    );
};
