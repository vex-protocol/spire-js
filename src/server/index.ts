import type { Database } from "../Database.ts";
import type { Emoji } from "@vex-chat/types";
import type winston from "winston";

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import { type KeyPair, xSignOpen } from "@vex-chat/crypto";
import { PreKeysWSSchema, TokenScopes, UserSchema } from "@vex-chat/types";

import cors from "cors";
import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import morgan from "morgan";
import multer from "multer";
import parseDuration from "parse-duration";
import { stringify as uuidStringify } from "uuid";
import { z } from "zod/v4";

import { POWER_LEVELS } from "../ClientManager.ts";
import { JWT_EXPIRY } from "../Spire.ts";
import { getJwtSecret } from "../utils/jwtSecret.ts";
import { msgpack } from "../utils/msgpack.ts";

import { getAvatarRouter } from "./avatar.ts";
import { getFileRouter } from "./file.ts";
import { getInviteRouter } from "./invite.ts";
import { setupOpenApiDocs } from "./openapi.ts";
import {
    hasAnyPermission,
    hasPermission,
    userHasPermission,
} from "./permissions.ts";
import { getUserRouter } from "./user.ts";
import { censorUser, getParam, getUser } from "./utils.ts";

// expiry of regkeys
export const EXPIRY_TIME = 1000 * 60 * 5;

export const ALLOWED_IMAGE_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/apng",
    "image/avif",
];

// ── Zod schemas for trust-boundary validation ──────────────────────────
const invitePayload = z.object({
    duration: z.string().min(1),
    serverID: z.string().min(1),
});

const channelPayload = z.object({
    name: z.string().min(1).max(255),
});

const deviceListPayload = z.array(z.string());

const connectPayload = z.object({
    signed: z.custom<Uint8Array>((val) => val instanceof Uint8Array),
});

const safePathParam = z.string().regex(/^[a-zA-Z0-9._-]+$/);

const emojiPayload = z.object({
    file: z.string().optional(),
    name: z.string().min(1),
    signed: z.string().optional(),
});

const jwtUserPayload = z.object({
    exp: z.number().optional(),
    user: UserSchema,
});

const jwtDevicePayload = z.object({
    device: z.object({
        deleted: z.boolean(),
        deviceID: z.string(),
        lastLogin: z.string(),
        name: z.string(),
        owner: z.string(),
        signKey: z.string(),
    }),
});

/** Extract Bearer token from Authorization header. */
function extractBearer(req: express.Request): null | string {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return null;
    return header.slice(7);
}

const checkAuth: express.RequestHandler = (req, _res, next) => {
    const token = extractBearer(req);
    if (token) {
        try {
            const result = jwt.verify(token, getJwtSecret());
            const parsed = jwtUserPayload.safeParse(result);
            if (parsed.success) {
                req.user = parsed.data.user;
                if (parsed.data.exp !== undefined) {
                    req.exp = parsed.data.exp;
                }
                req.bearerToken = token;
            }
        } catch {
            // Token verification failed — continue without auth
        }
    }
    next();
};

const checkDevice: express.RequestHandler = (req, _res, next) => {
    const token = req.headers["x-device-token"];
    if (typeof token === "string" && token) {
        try {
            const result = jwt.verify(token, getJwtSecret());
            const parsed = jwtDevicePayload.safeParse(result);
            if (parsed.success) {
                req.device = parsed.data.device;
            }
        } catch {
            // Device token verification failed — continue without device
        }
    }
    next();
};

export const protect: express.RequestHandler = (req, res, next) => {
    if (!req.user) {
        res.sendStatus(401);
        return;
    }

    next();
};

export const msgpackParser: express.RequestHandler = (req, res, next) => {
    if (req.is("application/msgpack")) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument -- Express req.body is any; decoded body is validated by route-level Zod schemas
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
    signKeys: KeyPair,
    notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ) => void,
) => {
    // INIT ROUTERS
    const userRouter = getUserRouter(db, log, tokenValidator);
    const fileRouter = getFileRouter(db, log);
    const avatarRouter = getAvatarRouter(db, log);
    const inviteRouter = getInviteRouter(db, log, tokenValidator, notify);

    // MIDDLEWARE
    api.use(express.json({ limit: "20mb" }));
    api.use(
        express.raw({
            limit: "20mb",
            type: "application/msgpack",
        }),
    );
    api.use(helmet());
    api.use(msgpackParser);
    api.use(checkAuth);
    api.use(checkDevice);

    if (!jestRun()) {
        api.use(morgan("dev", { stream: process.stdout }));
    }

    api.use(cors({ credentials: true }));

    api.get("/server/:id", protect, async (req, res) => {
        const server = await db.retrieveServer(getParam(req, "id"));

        if (server) {
            return res.send(msgpack.encode(server));
        } else {
            return res.sendStatus(404);
        }
    });

    api.post("/server/:name", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverName = atob(getParam(req, "name"));

        const server = await db.createServer(serverName, userDetails.userID);
        res.send(msgpack.encode(server));
    });

    api.post("/server/:serverID/invites", protect, async (req, res) => {
        const userDetails = getUser(req);

        const parsedPayload = invitePayload.safeParse(req.body);
        if (!parsedPayload.success) {
            res.status(400).json({
                error: "Invalid invite payload",
                issues: parsedPayload.error.issues,
            });
            return;
        }
        const payload = parsedPayload.data;
        const serverEntry = await db.retrieveServer(getParam(req, "serverID"));

        if (!serverEntry) {
            res.sendStatus(404);
            return;
        }

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );

        if (
            !hasPermission(
                permissions,
                getParam(req, "serverID"),
                POWER_LEVELS.INVITE,
            )
        ) {
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
        const userDetails = getUser(req);

        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );

        if (
            !hasPermission(
                permissions,
                getParam(req, "serverID"),
                POWER_LEVELS.INVITE,
            )
        ) {
            res.sendStatus(401);
            return;
        }

        const inviteList = await db.retrieveServerInvites(
            getParam(req, "serverID"),
        );
        res.send(msgpack.encode(inviteList));
    });

    api.delete("/server/:id", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverID = getParam(req, "id");
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (hasPermission(permissions, serverID, POWER_LEVELS.DELETE)) {
            await db.deleteServer(serverID);
            res.sendStatus(200);
            return;
        }
        res.sendStatus(401);
    });

    api.post("/server/:id/channels", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverID = getParam(req, "id");
        // resourceID is serverID
        const parsedBody = channelPayload.safeParse(req.body);
        if (!parsedBody.success) {
            res.status(400).json({
                error: "Invalid channel payload",
                issues: parsedBody.error.issues,
            });
            return;
        }
        const { name } = parsedBody.data;
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (hasPermission(permissions, serverID, POWER_LEVELS.CREATE)) {
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
        res.sendStatus(401);
    });

    api.get("/server/:id/channels", protect, async (req, res) => {
        const serverID = getParam(req, "id");
        const userDetails = getUser(req);
        const permissions = await db.retrievePermissions(
            userDetails.userID,
            "server",
        );
        if (hasAnyPermission(permissions, serverID)) {
            const channels = await db.retrieveChannels(serverID);
            res.send(msgpack.encode(channels));
            return;
        }
        res.sendStatus(401);
    });

    api.get("/server/:serverID/emoji", protect, async (req, res) => {
        const rows = await db.retrieveEmojiList(getParam(req, "serverID"));
        res.send(msgpack.encode(rows));
    });

    api.get("/server/:serverID/permissions", protect, async (req, res) => {
        const userDetails = getUser(req);
        const serverID = getParam(req, "serverID");
        try {
            const permissions =
                await db.retrievePermissionsByResourceID(serverID);
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
        } catch (err: unknown) {
            res.status(500).send(String(err));
        }
    });

    api.delete("/channel/:id", protect, async (req, res) => {
        const channelID = getParam(req, "id");
        const userDetails = getUser(req);

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
        const channel = await db.retrieveChannel(getParam(req, "id"));

        if (channel) {
            return res.send(msgpack.encode(channel));
        } else {
            return res.sendStatus(404);
        }
    });

    api.delete("/permission/:permissionID", protect, async (req, res) => {
        const permissionID = getParam(req, "permissionID");
        const userDetails = getUser(req);
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
                    await db.deletePermission(permToDelete.permissionID);
                    res.sendStatus(200);
                    return;
                }
            }
            res.sendStatus(401);
            return;
        } catch (err: unknown) {
            res.status(500).send(String(err));
        }
    });

    api.post("/userList/:channelID", async (req, res) => {
        const userDetails = getUser(req);
        const channelID = getParam(req, "channelID");

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
        } catch (err: unknown) {
            log.error(String(err));
            res.status(500).send(String(err));
        }
    });

    api.post("/deviceList", protect, async (req, res) => {
        const parsed = deviceListPayload.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Expected array of user ID strings",
                issues: parsed.error.issues,
            });
            return;
        }
        const devices = await db.retrieveUserDeviceList(parsed.data);
        res.send(msgpack.encode(devices));
    });

    api.get("/device/:id", protect, async (req, res) => {
        const device = await db.retrieveDevice(getParam(req, "id"));

        if (device) {
            return res.send(msgpack.encode(device));
        } else {
            return res.sendStatus(404);
        }
    });

    api.post("/device/:id/keyBundle", protect, async (req, res) => {
        try {
            const keyBundle = await db.getKeyBundle(getParam(req, "id"));
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
        const deviceDetails = req.device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }
        try {
            const inbox = await db.retrieveMail(deviceDetails.deviceID);
            res.send(msgpack.encode(inbox));
        } catch (err: unknown) {
            res.status(500).send(String(err));
        }
    });

    api.post("/device/:id/connect", protect, async (req, res) => {
        const parsedBody = connectPayload.safeParse(req.body);
        if (!parsedBody.success) {
            res.status(400).json({
                error: "Invalid connect payload",
                issues: parsedBody.error.issues,
            });
            return;
        }
        const { signed } = parsedBody.data;
        const device = await db.retrieveDevice(getParam(req, "id"));
        if (!device) {
            res.sendStatus(404);
            return;
        }

        const regKey = xSignOpen(signed, XUtils.decodeHex(device.signKey));
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
        const deviceDetails = req.device;
        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        try {
            const count = await db.getOTKCount(deviceDetails.deviceID);
            res.send(msgpack.encode({ count }));
            return;
        } catch (err: unknown) {
            res.status(500).send(String(err));
        }
    });

    api.post("/device/:id/otk", protect, async (req, res) => {
        const parsedOTKs = z.array(PreKeysWSSchema).safeParse(req.body);
        if (!parsedOTKs.success) {
            res.status(400).json({
                error: "Invalid OTK payload",
                issues: parsedOTKs.error.issues,
            });
            return;
        }
        const submittedOTKs = parsedOTKs.data;
        if (submittedOTKs.length === 0) {
            res.sendStatus(200);
            return;
        }

        const userDetails = getUser(req);

        const deviceID = getParam(req, "id");
        const otk = submittedOTKs[0];

        const device = await db.retrieveDevice(deviceID);
        if (!device || !otk) {
            res.sendStatus(404);
            return;
        }

        const message = xSignOpen(
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
        } catch (err: unknown) {
            res.status(500).send(String(err));
        }
    });

    api.get("/emoji/:emojiID/details", protect, async (req, res) => {
        const emoji = await db.retrieveEmoji(getParam(req, "emojiID"));
        res.send(msgpack.encode(emoji));
    });

    api.get("/emoji/:emojiID", protect, async (req, res) => {
        const safeId = safePathParam.safeParse(getParam(req, "emojiID"));
        if (!safeId.success) {
            res.sendStatus(400);
            return;
        }
        const filePath = "./emoji/" + safeId.data;
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
        const parsedPayload = emojiPayload.safeParse(req.body);
        if (!parsedPayload.success) {
            res.status(400).json({
                error: "Invalid emoji payload",
                issues: parsedPayload.error.issues,
            });
            return;
        }
        const payload = parsedPayload.data;

        const userDetails = getUser(req);
        const device = req.device;

        if (!device) {
            res.sendStatus(401);
            return;
        }

        if (!payload.file) {
            res.sendStatus(400);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));
        const serverEntry = await db.retrieveServer(getParam(req, "serverID"));

        const permissionList = await db.retrievePermissionsByResourceID(
            getParam(req, "serverID"),
        );

        if (
            !userHasPermission(
                permissionList,
                userDetails.userID,
                POWER_LEVELS.EMOJI,
            )
        ) {
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
            log.warn("File too big.");
            res.sendStatus(413);
        }

        const mimeType = await fileTypeFromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                    String(mimeType?.ext),
            });
            return;
        }

        const emoji: Emoji = {
            emojiID: crypto.randomUUID(),
            name: payload.name,
            owner: getParam(req, "serverID"),
        };

        await db.createEmoji(emoji);

        try {
            // write the file to disk
            await fsp.writeFile("emoji/" + emoji.emojiID, buf);
            log.info("Wrote new emoji " + emoji.emojiID);
            res.send(msgpack.encode(emoji));
        } catch (err: unknown) {
            log.warn(String(err));
            res.sendStatus(500);
        }
    });

    api.post(
        "/emoji/:serverID",
        protect,
        multer().single("emoji"),
        async (req, res) => {
            const parsedPayload = emojiPayload.safeParse(req.body);
            if (!parsedPayload.success) {
                res.status(400).json({
                    error: "Invalid emoji payload",
                    issues: parsedPayload.error.issues,
                });
                return;
            }
            const payload = parsedPayload.data;
            const serverID = getParam(req, "serverID");
            if (typeof serverID !== "string") {
                res.sendStatus(400);
                return;
            }
            const serverEntry = await db.retrieveServer(serverID);
            const userDetails = getUser(req);
            const deviceDetails = req.device;
            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            const permissionList =
                await db.retrievePermissionsByResourceID(serverID);

            if (
                !userHasPermission(
                    permissionList,
                    userDetails.userID,
                    POWER_LEVELS.EMOJI,
                )
            ) {
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
                log.warn("MISSING FILE");
                res.sendStatus(400);
                return;
            }

            if (Buffer.byteLength(req.file.buffer) > 256000) {
                log.warn("File too big.");
                res.sendStatus(413);
            }

            const mimeType = await fileTypeFromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, or avif but received " +
                        String(mimeType?.ext),
                });
                return;
            }

            const emoji: Emoji = {
                emojiID: crypto.randomUUID(),
                name: payload.name,
                owner: serverID,
            };

            await db.createEmoji(emoji);

            try {
                // write the file to disk
                await fsp.writeFile("emoji/" + emoji.emojiID, req.file.buffer);
                log.info("Wrote new emoji " + emoji.emojiID);
                res.send(msgpack.encode(emoji));
            } catch (err: unknown) {
                log.warn(String(err));
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
    return process.env["JEST_WORKER_ID"] !== undefined;
};
