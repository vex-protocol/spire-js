import * as fs from "node:fs";
import * as path from "node:path";

import { XUtils } from "@vex-chat/crypto";
import { TokenScopes } from "@vex-chat/types";
import express from "express";
import FileType from "file-type";
import { msgpack } from "../utils/msgpack.js";
import multer from "multer";
import nacl from "tweetnacl";
import * as uuid from "uuid";
import winston from "winston";

import parseDuration from "parse-duration";

import { POWER_LEVELS } from "../ClientManager.js";
import { Database } from "../Database.js";

import { protect } from "./index.js";
import type { ICensoredUser } from "./utils.js";

export const getInviteRouter = (
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string
    ) => void
) => {
    const router = express.Router();
    router.patch("/:inviteID", protect, async (req, res) => {
        const userDetails: ICensoredUser = (req as any).user;

        const invite = await db.retrieveInvite(req.params.inviteID);
        if (!invite) {
            res.sendStatus(404);
            return;
        }

        if (new Date(invite.expiration).getTime() < Date.now()) {
            res.sendStatus(401);
            return;
        }

        const permission = await db.createPermission(
            userDetails.userID,
            "server",
            invite.serverID,
            0
        );
        res.send(msgpack.encode(permission));
        notify(userDetails.userID, "permission", uuid.v4(), permission);
    });

    router.get("/:inviteID", protect, async (req, res) => {
        const invite = await db.retrieveInvite(req.params.inviteID);
        if (!invite) {
            res.sendStatus(404);
            return;
        }
        res.send(msgpack.encode(invite));
    });

    return router;
};
