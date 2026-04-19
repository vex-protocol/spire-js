/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Centralized HTTP error handling.
 *
 * Fixes two classes of CodeQL findings:
 *
 * - **CWE-209 / CWE-497 — Information exposure through stack trace.**
 *   Previously, every route catch block did
 *   `res.status(500).send(String(err))`, leaking raw error objects
 *   (which include database internals, file paths, and stack traces)
 *   back to the client. The new pattern: throw `AppError(status, msg)`
 *   or let an unknown error propagate, and the single 4-arg middleware
 *   below converts it into a JSON response with a generic message.
 *
 * - **CWE-79 / CWE-116 — Exception text reinterpreted as HTML.** Express's
 *   default finalhandler sends thrown `Error` objects as
 *   `Content-Type: text/html`, which means `throw new Error("bad param: "
 *   + req.params.name)` became reflected XSS when the error page
 *   rendered. The handler below ALWAYS sends `application/json`, so
 *   even if a message somehow contains user input, the browser can't
 *   execute it. The companion fix is `getParam()` in `utils.ts` now
 *   throwing `AppError(400, "Missing route parameter")` with no user
 *   input in the message string.
 *
 * Express 5 has native async support, so throwing from an async
 * handler auto-forwards to `next(err)` and hits this middleware. No
 * `express-async-errors` shim needed.
 */
import type { ErrorRequestHandler } from "express";

import { randomUUID } from "node:crypto";

import { ZodError } from "zod/v4";

/**
 * Operational HTTP errors that are safe to surface to the client.
 *
 * - `status` — HTTP status code (400, 401, 403, 404, 409, etc.)
 * - `message` — client-safe message, MUST NOT contain request data
 *   (route params, body fields, query strings). Anything operator-
 *   only (database errors, file paths) should not appear in this string.
 *
 * Anything that isn't an `AppError` (raw `Error`, `TypeError`, a
 * rejected promise from a DB query, etc.) is treated by the central
 * handler as a **programmer error** — the client gets a generic 500
 * with no detail, and the real error is logged server-side.
 */
export class AppError extends Error {
    public readonly status: number;

    constructor(status: number, message: string) {
        super(message);
        this.name = "AppError";
        this.status = status;
    }
}

/**
 * Factory producing the central Express 5 error middleware.
 *
 * Register this as the LAST middleware in the app, after every
 * route and router has been mounted:
 *
 *     api.use("/user", userRouter);
 *     // ... all other routers ...
 *     api.use(errorHandler(log));
 */
export const errorHandler =
    (): ErrorRequestHandler => (err, _req, res, _next) => {
        // If headers already went out there's nothing safe to do except
        // let Express's default handler close the socket.
        if (res.headersSent) {
            _next(err);
            return;
        }

        const requestId = randomUUID();

        let status = 500;
        let clientMessage = "Internal Server Error";
        let details: unknown;

        if (err instanceof ZodError) {
            // Validation failure at a trust boundary. The issue list is
            // structured JSON (no raw user input as a rendered string),
            // so it's safe to surface to help clients fix their payload.
            status = 400;
            clientMessage = "Validation failed";
            details = err.issues;
        } else if (err instanceof AppError) {
            status = err.status;
            clientMessage = err.message;
        }

        // ALWAYS JSON — prevents the exception-text-as-HTML XSS vector.
        res.status(status)
            .type("application/json")
            .json({
                error: {
                    message: clientMessage,
                    requestId,
                    ...(details !== undefined ? { details } : {}),
                },
            });
    };
