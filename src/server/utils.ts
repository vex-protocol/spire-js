/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Device, User, UserRecord } from "@vex-chat/types";
import type { Request } from "express";

import { AppError } from "./errors.ts";

/**
 * Strips password fields from a DB user record, returning the
 * public-safe User shape.
 */
export const censorUser = (user: UserRecord): User => {
    return {
        lastSeen: user.lastSeen,
        userID: user.userID,
        username: user.username,
    };
};

/**
 * Safely extract the authenticated device from a request.
 * Throws if the device is not set (i.e. checkDevice middleware did
 * not run or the token was not a device token).
 *
 * Throws `AppError(401)` — the central error handler turns this into
 * a JSON 401 response. No stack trace or raw Error leaks.
 */
export function getDevice(req: Request): Device {
    if (!req.device) throw new AppError(401, "Not authenticated");
    return req.device;
}

/**
 * Safely extract a required route parameter.
 *
 * Throws `AppError(400)` if the parameter is missing or is an array
 * (which shouldn't happen for well-wired routes, but defensively
 * checked). The error message deliberately does NOT include the
 * user-supplied value — CWE-79 / CWE-116 fix for the earlier
 * `"Missing route parameter: " + name` concatenation pattern.
 */
export function getParam(req: Request, name: string): string {
    const value = req.params[name];
    if (!value || Array.isArray(value)) {
        throw new AppError(400, "Missing or invalid route parameter");
    }
    return value;
}

/**
 * Safely extract the authenticated user from a request.
 * Throws if the user is not set (i.e. protect middleware was not
 * applied to this route).
 *
 * Throws `AppError(401)` — the central error handler turns this into
 * a JSON 401 response.
 */
export function getUser(req: Request): User {
    if (!req.user) throw new AppError(401, "Not authenticated");
    return req.user;
}
