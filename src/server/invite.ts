import type { Database } from "../Database.ts";
import type { TokenScopes } from "@vex-chat/types";

import express from "express";

import { msgpack } from "../utils/msgpack.ts";

import { getParam, getUser } from "./utils.ts";

import { protect } from "./index.ts";

export const getInviteRouter = (
    db: Database,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void,
) => {
    const router = express.Router();
    router.patch("/:inviteID", protect, async (req, res) => {
        const userDetails = getUser(req);

        const invite = await db.retrieveInvite(getParam(req, "inviteID"));
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
            0,
        );
        res.send(msgpack.encode(permission));
        notify(
            userDetails.userID,
            "permission",
            crypto.randomUUID(),
            permission,
        );
    });

    router.get("/:inviteID", protect, async (req, res) => {
        const invite = await db.retrieveInvite(getParam(req, "inviteID"));
        if (!invite) {
            res.sendStatus(404);
            return;
        }
        res.send(msgpack.encode(invite));
    });

    return router;
};
