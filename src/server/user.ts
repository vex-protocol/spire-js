/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Database } from "../Database.ts";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import { DevicePayloadSchema, TokenScopes } from "@vex-chat/types";

import { stringify } from "uuid";

import { msgpack } from "../utils/msgpack.ts";
import { spireXSignOpenAsync } from "../utils/spireXSignOpenAsync.ts";

import { censorUser, getParam, getUser } from "./utils.ts";

import { protect } from "./index.ts";

export const getUserRouter = (
    db: Database,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
) => {
    const router = express.Router();

    router.get("/:id", protect, async (req, res) => {
        const user = await db.retrieveUser(getParam(req, "id"));

        if (user) {
            return res.send(msgpack.encode(censorUser(user)));
        } else {
            return res.sendStatus(404);
        }
    });

    router.get("/:id/devices", protect, async (req, res) => {
        const id = getParam(req, "id");
        const user = await db.retrieveUser(id);
        if (!user) {
            res.sendStatus(404);
            return;
        }
        const deviceList = await db.retrieveUserDeviceList([id]);
        return res.send(msgpack.encode(deviceList));
    });

    router.get("/:id/permissions", protect, async (req, res) => {
        const userDetails = getUser(req);
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "all",
        );
        res.send(msgpack.encode(permissions));
    });

    router.get("/:id/servers", protect, async (req, res) => {
        const userDetails = getUser(req);
        const servers = await db.retrieveServers(userDetails.userID);
        res.send(msgpack.encode(servers));
    });

    router.delete("/:userID/devices/:deviceID", protect, async (req, res) => {
        const device = await db.retrieveDevice(getParam(req, "deviceID"));

        if (!device) {
            res.sendStatus(404);
            return;
        }
        const userDetails = getUser(req);
        if (userDetails.userID !== device.owner) {
            res.sendStatus(401);
            return;
        }
        const deviceList = await db.retrieveUserDeviceList([
            userDetails.userID,
        ]);
        if (deviceList.length === 1) {
            res.status(400).send({
                error: "You can't delete your last device.",
            });
            return;
        }

        await db.deleteDevice(device.deviceID);
        res.sendStatus(200);
    });

    router.post("/:id/devices", protect, async (req, res) => {
        const userDetails = getUser(req);
        const parsed = DevicePayloadSchema.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid device payload",
                issues: parsed.error.issues,
            });
            return;
        }
        const deviceData = parsed.data;

        const token = await spireXSignOpenAsync(
            XUtils.decodeHex(deviceData.signed),
            XUtils.decodeHex(deviceData.signKey),
        );

        if (!token) {
            res.sendStatus(400);
            return;
        }

        if (tokenValidator(stringify(token), TokenScopes.Device)) {
            try {
                const device = await db.createDevice(
                    userDetails.userID,
                    deviceData,
                );
                res.send(msgpack.encode(device));
            } catch (_err: unknown) {
                // signkey already taken
                res.sendStatus(470);
                return;
            }
        } else {
            res.sendStatus(401);
        }
    });

    return router;
};
