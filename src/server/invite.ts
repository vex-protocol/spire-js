import { TokenScopes } from "@vex-chat/types";
import express from "express";
import * as uuid from "uuid";
import winston from "winston";

import { msgpack } from "../utils/msgpack.ts";
import { POWER_LEVELS } from "../ClientManager.ts";
import { Database } from "../Database.ts";
import { protect } from "./index.ts";
import type { ICensoredUser } from "./utils.ts";

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
