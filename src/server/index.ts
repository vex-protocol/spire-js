import type { Database } from "../Database.ts";
import type { IDevice, IEmoji, IPreKeysWS } from "@vex-chat/types";
import type { IUser } from "@vex-chat/types";
import type winston from "winston";

import * as fs from "node:fs";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import { TokenScopes } from "@vex-chat/types";

import cors from "cors";
import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import morgan from "morgan";
import multer from "multer";
import parseDuration from "parse-duration";
import nacl from "tweetnacl";
import { stringify as uuidStringify } from "uuid";

import { POWER_LEVELS } from "../ClientManager.ts";
import { JWT_EXPIRY } from "../Spire.ts";
import { getJwtSecret } from "../utils/jwtSecret.ts";
import { msgpack } from "../utils/msgpack.ts";

import { getAvatarRouter } from "./avatar.ts";
import { getFileRouter } from "./file.ts";
import { getInviteRouter } from "./invite.ts";
import { setupOpenApiDocs } from "./openapi.ts";
import { getUserRouter } from "./user.ts";
import { censorUser } from "./utils.ts";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

export const ALLOWED_IMAGE_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/apng",
    "image/avif",
];

interface IInvitePayload {
    duration: string;
    serverID: string;
}

/** Extract Bearer token from Authorization header. */
function extractBearer(req: any): null | string {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return null;
    return header.slice(7);
}

const checkAuth = (req: any, res: any, next: () => void) => {
    const token = extractBearer(req);
    if (token) {
        try {
            const result = jwt.verify(token, getJwtSecret());
            req.user = (result as any).user;
            req.exp = (result as any).exp;
            req.bearerToken = token;
        } catch (err) {
            console.warn(err.toString());
        }
    }
    next();
};

const checkDevice = (req: any, res: any, next: () => void) => {
    const token = req.headers["x-device-token"];
    if (token) {
        try {
            const result = jwt.verify(token, getJwtSecret());
            req.device = (result as any).device;
        } catch (err) {
            console.warn(err.toString());
        }
    }
    next();
};

export const protect = (req: any, res: any, next: () => void) => {
    if (!req.user) {
        res.sendStatus(401);
        throw new Error("not authenticated!");
    }

    next();
};

export const msgpackParser = (req: any, res: any, next: () => void) => {
    if (req.is("application/msgpack")) {
        try {
            req.body = msgpack.decode(req.body);
        } catch {
            res.sendStatus(400);
            return;
        }
    }
    next();
};

const directories = ["files", "avatars"];
for (const dir of directories) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
}

export const initApp = (
    api: express.Application,
    db: Database,
    log: winston.Logger,
    tokenValidator: (key: string, scope: TokenScopes) => boolean,
    signKeys: nacl.SignKeyPair,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string,
    ) => void,
) => {
    // INIT ROUTERS
    const userRouter = getUserRouter(db, log, tokenValidator);
    const fileRouter = getFileRouter(db, log);
    const avatarRouter = getAvatarRouter(db, log);
    const inviteRouter = getInviteRouter(db, log, tokenValidator, notify);

    // MIDDLEWARE — cast to `any` for overload resolution with raw/json parsers
    const apiAny = api as any;
    apiAny.use(express.json({ limit: "20mb" }));
    apiAny.use(
        express.raw({
            limit: "20mb",
            type: "application/msgpack",
        }),
    );
    apiAny.use(helmet());
    apiAny.use(msgpackParser);
    apiAny.use(checkAuth);
    apiAny.use(checkDevice);

    if (!jestRun()) {
        apiAny.use(morgan("dev", { stream: process.stdout }));
    }

    apiAny.use(cors({ credentials: true }));

    api.get("/server/:id", protect, async (req, res) => {
        const server = await db.retrieveServer(req.params.id);

        if (server) {
            return res.send(msgpack.encode(server));
        } else {
            return res.sendStatus(404);
        }
    });

    api.post("/server/:name", protect, async (req, res) => {
        const userDetails: IUser = (req as any).user;
        const serverName = atob(req.params.name);

        const server = await db.createServer(serverName, userDetails.userID);
        res.send(msgpack.encode(server));
    });

    api.post("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails: IUser = (req as any).user;

        const payload: IInvitePayload = req.body;
        const serverEntry = await db.retrieveServer(req.params.serverID);

        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );

        let hasPermission = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPermission = true;
            }
        }

        if (!hasPermission) {
            log.warn("No permission!");
            res.sendStatus(401);
            return;
        }

        const duration = parseDuration(payload.duration, "ms");

        if (!duration) {
            res.sendStatus(400);
            return;
        }

        const expires = new Date(Date.now() + duration);

        const invite = await db.createInvite(
            crypto.randomUUID(),
            serverEntry.serverID,
            userDetails.userID,
            expires.toString(),
        );
        res.send(msgpack.encode(invite));
    });

    api.get("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails: IUser = (req as any).user;

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );

        let hasPermission = false;
        for (const permission of permissions) {
            if (
                permission.resourceID === req.params.serverID &&
                permission.powerLevel > POWER_LEVELS.INVITE
            ) {
                hasPermission = true;
            }
        }
        if (!hasPermission) {
            res.sendStatus(401);
            return;
        }

        const inviteList = await db.retrieveServerInvites(req.params.serverID);
        res.send(msgpack.encode(inviteList));
    });

    api.delete("/server/:id", protect, async (req, res) => {
        const userDetails = (req as any).user;
        const serverID = req.params.id;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        for (const permission of permissions) {
            if (
                permission.resourceID === serverID &&
                permission.powerLevel > POWER_LEVELS.DELETE
            ) {
                // msg.data is the serverID
                await db.deleteServer(serverID);
                res.sendStatus(200);
                return;
            }
        }
        res.sendStatus(401);
    });

    api.post("/server/:id/channels", protect, async (req, res) => {
        const userDetails: IUser = (req as any).user;
        const serverID = req.params.id;
        // resourceID is serverID
        const { name } = req.body;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        for (const permission of permissions) {
            if (
                permission.resourceID === serverID &&
                permission.powerLevel > POWER_LEVELS.CREATE
            ) {
                const channel = await db.createChannel(name, serverID);
                res.send(msgpack.encode(channel));

                const affectedUsers = await db.retrieveAffectedUsers(serverID);
                // tell everyone about server change
                for (const user of affectedUsers) {
                    notify(
                        user.userID,
                        "serverChange",
                        crypto.randomUUID(),
                        serverID,
                    );
                }
                return;
            }
        }
        res.sendStatus(401);
    });

    api.get("/server/:id/channels", protect, async (req, res) => {
        const serverID = req.params.id;
        const userDetails = (req as any).user;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        for (const permission of permissions) {
            if (serverID === permission.resourceID) {
                const channels = await db.retrieveChannels(
                    permission.resourceID,
                );
                res.send(msgpack.encode(channels));
                return;
            }
        }
        res.sendStatus(401);
    });

    api.get("/server/:serverID/emoji", protect, async (req, res) => {
        const rows = await db.retrieveEmojiList(req.params.serverID);
        res.send(msgpack.encode(rows));
    });

    api.get("/server/:serverID/permissions", protect, async (req, res) => {
        const userDetails: IUser = (req as any).user;
        const serverID = req.params.serverID;
        try {
            const permissions =
                await db.retrievePermissionsByResourceID(serverID);
            if (permissions) {
                let found = false;
                for (const perm of permissions) {
                    if (perm.userID === userDetails.userID) {
                        res.send(msgpack.encode(permissions));
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    res.sendStatus(401);
                    return;
                }
            } else {
                res.sendStatus(404);
            }
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.delete("/channel/:id", protect, async (req, res) => {
        const channelID = req.params.id;
        const userDetails: IUser = (req as any).user;

        const channel = await db.retrieveChannel(channelID);

        if (!channel) {
            res.sendStatus(401);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        for (const permission of permissions) {
            if (
                permission.resourceID === channel.serverID &&
                permission.powerLevel > 50
            ) {
                await db.deleteChannel(channelID);

                res.sendStatus(200);

                const affectedUsers = await db.retrieveAffectedUsers(
                    channel.serverID,
                );
                // tell everyone about server change
                for (const user of affectedUsers) {
                    notify(
                        user.userID,
                        "serverChange",
                        crypto.randomUUID(),
                        channel.serverID,
                    );
                }
                return;
            }
        }
        res.sendStatus(401);
    });

    api.get("/channel/:id", protect, async (req, res) => {
        const channel = await db.retrieveChannel(req.params.id);

        if (channel) {
            return res.send(msgpack.encode(channel));
        } else {
            return res.sendStatus(404);
        }
    });

    api.delete("/permission/:permissionID", protect, async (req, res) => {
        const permissionID = req.params.permissionID;
        const userDetails: IUser = (req as any).user;
        try {
            // msg.data is permID
            const permToDelete = await db.retrievePermission(permissionID);
            if (!permToDelete) {
                res.sendStatus(404);
                return;
            }

            const permissions = await db.retrievePermissions(
                userDetails.userID,
                permToDelete.resourceType,
            );

            for (const perm of permissions) {
                // msg.data is resourceID
                if (
                    perm.resourceID === permToDelete.resourceID &&
                    (perm.userID === userDetails.userID ||
                        (perm.powerLevel > POWER_LEVELS.DELETE &&
                            perm.powerLevel > permToDelete.powerLevel))
                ) {
                    db.deletePermission(permToDelete.permissionID);
                    res.sendStatus(200);
                    return;
                }
            }
            res.sendStatus(401);
            return;
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.post("/userList/:channelID", async (req, res) => {
        const userDetails: IUser = (req as any).user;
        const channelID: string = req.params.channelID;

        try {
            const channel = await db.retrieveChannel(channelID);
            if (!channel) {
                res.sendStatus(404);
                return;
            }
            const permissions = await db.retrievePermissions(
                userDetails.userID,
                "server",
            );
            for (const permission of permissions) {
                if (permission.resourceID === channel.serverID) {
                    // we've got the permission, it's ok to give them the userlist
                    const groupMembers =
                        await db.retrieveGroupMembers(channelID);
                    res.send(
                        msgpack.encode(
                            groupMembers.map((user) => censorUser(user)),
                        ),
                    );
                }
            }
        } catch (err) {
            log.error(err.toString());
            res.status(500).send(err.toString());
        }
    });

    api.post("/deviceList", protect, async (req, res) => {
        const userIDs: string[] = req.body;
        const devices = await db.retrieveUserDeviceList(userIDs);
        res.send(msgpack.encode(devices));
    });

    api.get("/device/:id", protect, async (req, res) => {
        const device = await db.retrieveDevice(req.params.id);

        if (device) {
            return res.send(msgpack.encode(device));
        } else {
            return res.sendStatus(404);
        }
    });

    api.post("/device/:id/keyBundle", protect, async (req, res) => {
        try {
            const keyBundle = await db.getKeyBundle(req.params.id);
            if (keyBundle) {
                res.send(msgpack.encode(keyBundle));
            } else {
                res.sendStatus(404);
            }
        } catch {
            res.sendStatus(500);
        }
    });

    api.post("/device/:id/mail", protect, async (req, res) => {
        const deviceDetails: IDevice | undefined = (req as any).device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }
        try {
            const inbox = await db.retrieveMail(deviceDetails.deviceID);
            res.send(msgpack.encode(inbox));
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.post("/device/:id/connect", protect, async (req, res) => {
        const { signed }: { signed: Uint8Array } = req.body;
        const device = await db.retrieveDevice(req.params.id);
        if (!device) {
            res.sendStatus(404);
            return;
        }

        const regKey = nacl.sign.open(signed, XUtils.decodeHex(device.signKey));
        if (
            regKey &&
            tokenValidator(uuidStringify(regKey), TokenScopes.Connect)
        ) {
            const token = jwt.sign({ device }, getJwtSecret(), {
                expiresIn: JWT_EXPIRY,
            });
            jwt.verify(token, getJwtSecret());

            res.send(msgpack.encode({ deviceToken: token }));
        } else {
            res.sendStatus(401);
        }
    });

    api.get("/device/:id/otk/count", protect, async (req, res) => {
        const deviceDetails: IDevice | undefined = (req as any).device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        try {
            const count = await db.getOTKCount(deviceDetails.deviceID);
            res.send(msgpack.encode({ count }));
            return;
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    api.post("/device/:id/otk", protect, async (req, res) => {
        const submittedOTKs: IPreKeysWS[] = req.body;
        if (submittedOTKs.length === 0) {
            res.sendStatus(200);
            return;
        }

        const userDetails = (req as any).user;

        const deviceID = req.params.id;
        const [otk] = submittedOTKs;

        const device = await db.retrieveDevice(deviceID);
        if (!device) {
            res.sendStatus(404);
            return;
        }

        const message = nacl.sign.open(
            otk.signature,
            XUtils.decodeHex(device.signKey),
        );

        if (!message) {
            res.sendStatus(401);
            return;
        }

        try {
            await db.saveOTK(userDetails.userID, deviceID, submittedOTKs);
            res.sendStatus(200);
        } catch (err) {
            res.status(500).send(err.toString());
        }
    });

    interface IEmojiPayload {
        file?: string;
        name: string;
        signed: string;
    }

    api.get("/emoji/:emojiID/details", protect, async (req, res) => {
        const emoji = await db.retrieveEmoji(req.params.emojiID);
        res.send(msgpack.encode(emoji));
    });

    api.get("/emoji/:emojiID", protect, async (req, res) => {
        const filePath = "./emoji/" + req.params.emojiID;
        const typeDetails = await fileTypeFromFile(filePath).catch(() => null);
        if (!typeDetails) {
            res.sendStatus(404);
            return;
        }
        res.set("Content-type", typeDetails.mime);
        res.set("Cache-control", "public, max-age=31536000");

        const stream = fs.createReadStream(filePath);
        stream.on("error", (err) => {
            log.error(err.toString());
            res.sendStatus(500);
        });
        stream.pipe(res);
    });

    api.post("/emoji/:serverID/json", protect, async (req, res) => {
        const payload: IEmojiPayload = req.body;

        const userDetails: IUser = (req as any).user;
        const device: IDevice | undefined = (req as any).device;

        if (!device) {
            res.sendStatus(401);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file!));
        const serverEntry = await db.retrieveServer(req.params.serverID);

        const permissionList = await db.retrievePermissionsByResourceID(
            req.params.serverID,
        );
        let hasPermission = false;
        for (const permission of permissionList) {
            if (
                permission.userID === userDetails.userID &&
                permission.powerLevel > POWER_LEVELS.EMOJI
            ) {
                hasPermission = true;
                break;
            }
        }

        if (!hasPermission) {
            res.sendStatus(401);
            return;
        }
        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }
        if (!payload.name) {
            res.sendStatus(400);
        }
        if (Buffer.byteLength(buf) > 256000) {
            console.warn("File to big.");
            res.sendStatus(413);
        }

        const mimeType = await fileTypeFromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                    mimeType?.ext,
            });
            return;
        }

        const emoji: IEmoji = {
            emojiID: crypto.randomUUID(),
            name: payload.name,
            owner: req.params.serverID,
        };

        await db.createEmoji(emoji);

        try {
            // write the file to disk
            fs.writeFile("emoji/" + emoji.emojiID, buf, () => {
                log.info("Wrote new emoji " + emoji.emojiID);
            });
            res.send(msgpack.encode(emoji));
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    api.post(
        "/emoji/:serverID",
        protect,
        multer().single("emoji"),
        async (req, res) => {
            const payload: IEmojiPayload = req.body;
            const serverID = req.params.serverID;
            if (typeof serverID !== "string") {
                res.sendStatus(400);
                return;
            }
            const serverEntry = await db.retrieveServer(serverID);
            const userDetails: IUser = (req as any).user;
            const deviceDetails: IDevice | undefined = (req as any).device;
            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            const permissionList =
                await db.retrievePermissionsByResourceID(serverID);
            let hasPermission = false;
            for (const permission of permissionList) {
                if (
                    permission.userID === userDetails.userID &&
                    permission.powerLevel > POWER_LEVELS.EMOJI
                ) {
                    hasPermission = true;
                    break;
                }
            }
            if (!hasPermission) {
                res.sendStatus(401);
                return;
            }

            if (!serverEntry) {
                res.sendStatus(404);
                return;
            }

            if (!payload.name) {
                res.sendStatus(400);
            }

            if (!req.file) {
                console.warn("MISSING FILE");
                res.sendStatus(400);
                return;
            }

            if (Buffer.byteLength(req.file.buffer) > 256000) {
                console.warn("File to big.");
                res.sendStatus(413);
            }

            const mimeType = await fileTypeFromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                        mimeType?.ext,
                });
                return;
            }

            const emoji: IEmoji = {
                emojiID: crypto.randomUUID(),
                name: payload.name,
                owner: serverID,
            };

            await db.createEmoji(emoji);

            try {
                // write the file to disk
                fs.writeFile("emoji/" + emoji.emojiID, req.file.buffer, () => {
                    log.info("Wrote new emoji " + emoji.emojiID);
                });
                res.send(msgpack.encode(emoji));
            } catch (err) {
                log.warn(err);
                res.sendStatus(500);
            }
        },
    );

    // COMPLEX RESOURCES
    api.use("/user", userRouter);

    api.use("/file", fileRouter);

    api.use("/avatar", avatarRouter);

    api.use("/invite", inviteRouter);

    setupOpenApiDocs(api, [
        { basePath: "/user", router: userRouter },
        { basePath: "/file", router: fileRouter },
        { basePath: "/avatar", router: avatarRouter },
        { basePath: "/invite", router: inviteRouter },
    ]);
};

/**
 * @ignore
 */
const jestRun = () => {
    return process.env.JEST_WORKER_ID !== undefined;
};
