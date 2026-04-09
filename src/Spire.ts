import type { ActionToken, BaseMsg, NotifyMsg, User } from "@vex-chat/types";
import type { Server } from "http";
import type winston from "winston";

import { EventEmitter } from "events";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import {
    type KeyPair,
    xRandomBytes,
    xSignKeyPairFromSecret,
    xSignOpen,
} from "@vex-chat/crypto";
import {
    MailWSSchema,
    RegistrationPayloadSchema,
    TokenScopes,
    UserSchema,
} from "@vex-chat/types";

import jwt from "jsonwebtoken";
import { stringify as uuidStringify } from "uuid";
import { WebSocketServer } from "ws";
import { z } from "zod/v4";

import { ClientManager } from "./ClientManager.ts";
import { Database, hashPassword } from "./Database.ts";
import { initApp, protect } from "./server/index.ts";
import { censorUser, getParam, getUser } from "./server/utils.ts";
import { createLogger } from "./utils/createLogger.ts";
import { getJwtSecret } from "./utils/jwtSecret.ts";
import { msgpack } from "./utils/msgpack.ts";

// expiry of regkeys = 24hr
export const TOKEN_EXPIRY = 1000 * 60 * 10;
export const JWT_EXPIRY = "7d";
export const DEVICE_AUTH_JWT_EXPIRY = "1h";
const DEVICE_CHALLENGE_EXPIRY = 1000 * 60; // 60 seconds
const STATUS_LATENCY_BUDGET_MS = 250;

// 3-19 chars long
const usernameRegex = /^(\w{3,19})$/;

// ── Zod schemas for trust-boundary validation ──────────────────────────
const wsAuthMsg = z.object({
    token: z.string().min(1),
    type: z.literal("auth"),
});

const jwtPayload = z.object({
    bearerToken: z.string().optional(),
    exp: z.number().optional(),
    user: UserSchema,
});

const authPayload = z.object({
    password: z.string().min(1),
    username: z.string().min(1),
});

const deviceAuthPayload = z.object({
    deviceID: z.string().min(1),
    signKey: z.string().min(1),
});

const deviceVerifyPayload = z.object({
    challengeID: z.string().min(1),
    signed: z.string().min(1),
});

const mailPostPayload = z.object({
    header: z.custom<Uint8Array>((val) => val instanceof Uint8Array),
    mail: MailWSSchema,
});

const directories = ["files", "avatars", "emoji"];
for (const dir of directories) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir);
    }
}

const getAppVersion = (): string => {
    try {
        const raw = fs.readFileSync(
            new URL("../package.json", import.meta.url),
            {
                encoding: "utf8",
            },
        );
        const pkg: unknown = JSON.parse(raw);
        if (
            typeof pkg === "object" &&
            pkg !== null &&
            "version" in pkg &&
            typeof pkg.version === "string"
        ) {
            return pkg.version;
        }
        return "unknown";
    } catch {
        return "unknown";
    }
};

const getCommitSha = (): string => {
    const sourceDir = path.dirname(fileURLToPath(import.meta.url));
    const repoRoot = path.resolve(sourceDir, "..");

    try {
        const sha = execSync("git rev-parse --verify --short=12 HEAD", {
            cwd: repoRoot,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 1500,
        }).trim();
        return sha || "unknown";
    } catch {
        return "unknown";
    }
};

export interface SpireOptions {
    apiPort?: number;
    dbType?: "mysql" | "sqlite3" | "sqlite3mem" | "sqlite";
    logLevel?:
        | "debug"
        | "error"
        | "http"
        | "info"
        | "silly"
        | "verbose"
        | "warn";
}

export class Spire extends EventEmitter {
    private actionTokens: ActionToken[] = [];
    private api = express();
    private clients: ClientManager[] = [];
    private readonly commitSha = getCommitSha();
    private db: Database;
    private dbReady = false;
    private deviceChallenges = new Map<
        string,
        { deviceID: string; nonce: string; time: number }
    >();
    private log: winston.Logger;
    private options: SpireOptions | undefined;

    private queuedRequestIncrements = 0;
    private requestsTotal = 0;

    private requestsTotalLoaded = false;

    private server: null | Server = null;
    private signKeys: KeyPair;

    private readonly startedAt = new Date();
    private readonly version = getAppVersion();
    private wss: WebSocketServer = new WebSocketServer({ noServer: true });

    constructor(SK: string, options?: SpireOptions) {
        super();
        this.signKeys = xSignKeyPairFromSecret(XUtils.decodeHex(SK));

        this.db = new Database(options);
        this.db.on("ready", () => {
            this.dbReady = true;
            this.bootstrapRequestCounter().catch((err: unknown) => {
                this.log.error(
                    "Failed to load persisted request counter: " + String(err),
                );
            });
        });

        this.log = createLogger("spire", options?.logLevel || "error");
        this.init(options?.apiPort || 16777);

        this.options = options;
    }

    public async close(): Promise<void> {
        this.wss.clients.forEach((ws) => {
            ws.terminate();
        });

        this.wss.on("close", () => {
            this.log.info("ws: closed.");
        });

        this.server?.on("close", () => {
            this.log.info("http: closed.");
        });

        this.server?.close();
        this.wss.close();
        await this.db.close();
        return;
    }

    private async bootstrapRequestCounter(): Promise<void> {
        const persistedTotal = await this.db.getRequestsTotal();
        const startupIncrements = this.queuedRequestIncrements;
        this.queuedRequestIncrements = 0;
        this.requestsTotal = persistedTotal + startupIncrements;
        if (startupIncrements > 0) {
            await this.db.incrementRequestsTotal(startupIncrements);
        }
        this.requestsTotalLoaded = true;
    }

    private createActionToken(scope: TokenScopes): ActionToken {
        const token: ActionToken = {
            key: crypto.randomUUID(),
            scope,
            time: new Date().toISOString(),
        };
        this.actionTokens.push(token);
        return token;
    }

    private deleteActionToken(key: ActionToken) {
        if (this.actionTokens.includes(key)) {
            this.actionTokens.splice(this.actionTokens.indexOf(key), 1);
        }
    }

    private init(apiPort: number): void {
        this.api.use((_req, _res, next) => {
            this.requestsTotal += 1;

            if (!this.requestsTotalLoaded) {
                this.queuedRequestIncrements += 1;
            } else {
                this.db.incrementRequestsTotal(1).catch((err: unknown) => {
                    this.log.warn(
                        "Failed to persist request counter increment: " +
                            String(err),
                    );
                });
            }

            next();
        });

        // initialize the expression app configuration with loose routes/handlers
        initApp(
            this.api,
            this.db,
            this.log,
            this.validateToken.bind(this),
            this.signKeys,
            this.notify.bind(this),
        );

        // WS auth: client sends { type: "auth", token } as first message
        this.wss.on("connection", (ws) => {
            this.log.info("WS connection established, waiting for auth...");
            const AUTH_TIMEOUT = 10_000;

            const timer = setTimeout(() => {
                this.log.warn("WS auth timeout — closing.");
                ws.close();
            }, AUTH_TIMEOUT);

            const onFirstMessage = (data: ArrayBuffer | Buffer | Buffer[]) => {
                const str = Buffer.isBuffer(data)
                    ? data.toString()
                    : data instanceof ArrayBuffer
                      ? Buffer.from(data).toString()
                      : Buffer.concat(data).toString();
                clearTimeout(timer);
                ws.off("message", onFirstMessage);

                try {
                    const rawParsed: unknown = JSON.parse(str);
                    const authResult = wsAuthMsg.safeParse(rawParsed);
                    if (!authResult.success) {
                        throw new Error(
                            "Expected { type: 'auth', token }, got: " +
                                JSON.stringify(authResult.error.issues),
                        );
                    }
                    const result = jwt.verify(
                        authResult.data.token,
                        getJwtSecret(),
                    );
                    const jwtResult = jwtPayload.safeParse(result);
                    if (!jwtResult.success) {
                        throw new Error(
                            "Invalid JWT payload: " +
                                JSON.stringify(jwtResult.error.issues),
                        );
                    }
                    const userDetails: User = jwtResult.data.user;

                    this.log.info(
                        "WS auth succeeded for " + userDetails.username,
                    );

                    const client = new ClientManager(
                        ws,
                        this.db,
                        this.notify.bind(this),
                        userDetails,
                        this.options,
                    );

                    client.on("fail", () => {
                        this.log.info(
                            "Client connection is down, removing: " +
                                client.toString(),
                        );
                        if (this.clients.includes(client)) {
                            this.clients.splice(
                                this.clients.indexOf(client),
                                1,
                            );
                        }
                        this.log.info(
                            "Current authorized clients: " +
                                String(this.clients.length),
                        );
                    });

                    client.on("authed", () => {
                        this.log.info(
                            "New client authorized: " + client.toString(),
                        );
                        this.clients.push(client);
                        this.log.info(
                            "Current authorized clients: " +
                                String(this.clients.length),
                        );
                    });
                } catch (err: unknown) {
                    this.log.warn("WS auth failed: " + String(err));
                    const errMsg: BaseMsg = {
                        transmissionID: crypto.randomUUID(),
                        type: "unauthorized",
                    };
                    ws.send(XUtils.packMessage(errMsg));
                    ws.close();
                }
            };

            ws.on("message", onFirstMessage);
            ws.on("close", () => {
                clearTimeout(timer);
            });
        });

        this.api.get(
            "/token/:tokenType",
            (req, res, next) => {
                if (getParam(req, "tokenType") !== "register") {
                    protect(req, res, next);
                } else {
                    next();
                }
            },
            (req, res) => {
                const allowedTokens = [
                    "file",
                    "register",
                    "avatar",
                    "device",
                    "invite",
                    "emoji",
                    "connect",
                ];

                const tokenType = getParam(req, "tokenType");

                if (!allowedTokens.includes(tokenType)) {
                    res.sendStatus(400);
                    return;
                }

                let scope;

                switch (tokenType) {
                    case "avatar":
                        scope = TokenScopes.Avatar;
                        break;
                    case "connect":
                        scope = TokenScopes.Connect;
                        break;
                    case "device":
                        scope = TokenScopes.Device;
                        break;
                    case "emoji":
                        scope = TokenScopes.Emoji;
                        break;
                    case "file":
                        scope = TokenScopes.File;
                        break;
                    case "invite":
                        scope = TokenScopes.Invite;
                        break;
                    case "register":
                        scope = TokenScopes.Register;
                        break;
                    default:
                        res.sendStatus(400);
                        return;
                }

                try {
                    this.log.info("New token requested of type " + tokenType);
                    const token = this.createActionToken(scope);
                    this.log.info("New token created: " + token.key);

                    setTimeout(() => {
                        this.deleteActionToken(token);
                    }, TOKEN_EXPIRY);

                    const acceptHeader = req.get("accept")?.toLowerCase() || "";
                    const wantsJson =
                        acceptHeader.includes("application/json") &&
                        !acceptHeader.includes("application/msgpack") &&
                        !acceptHeader.includes("*/*");

                    if (wantsJson) {
                        return res.json(token);
                    }

                    res.set("Content-Type", "application/msgpack");
                    return res.send(msgpack.encode(token));
                } catch (err: unknown) {
                    this.log.error(String(err));
                    return res.sendStatus(500);
                }
            },
        );

        this.api.post("/whoami", (req, res) => {
            if (!req.user) {
                res.sendStatus(401);
                return;
            }

            res.send(
                msgpack.encode({
                    exp: req.exp,
                    token: req.bearerToken,
                    user: req.user,
                }),
            );
        });

        this.api.get("/healthz", (_req, res) => {
            if (!this.dbReady) {
                res.status(503).json({ dbReady: false, ok: false });
                return;
            }
            res.json({ dbReady: true, ok: true });
        });

        this.api.get("/status", async (_req, res) => {
            const started = Date.now();
            const dbHealthy = this.dbReady ? await this.db.isHealthy() : false;
            const checkDurationMs = Date.now() - started;

            const ok = dbHealthy;
            res.json({
                checkDurationMs,
                commitSha: this.commitSha,
                dbHealthy,
                dbReady: this.dbReady,
                latencyBudgetMs: STATUS_LATENCY_BUDGET_MS,
                metrics: {
                    requestsTotal: this.requestsTotal,
                },
                now: new Date(),
                ok,
                startedAt: this.startedAt.toISOString(),
                uptimeSeconds: Math.floor(process.uptime()),
                version: this.version,
                withinLatencyBudget:
                    checkDurationMs <= STATUS_LATENCY_BUDGET_MS,
            });
        });

        this.api.post("/goodbye", protect, (req, res) => {
            jwt.sign({ user: req.user }, getJwtSecret(), { expiresIn: -1 });
            res.sendStatus(200);
        });

        // ── Device-key auth ──────────────────────────────────────────

        this.api.post("/auth/device", async (req, res) => {
            try {
                const parsed = deviceAuthPayload.safeParse(req.body);
                if (!parsed.success) {
                    return res
                        .status(400)
                        .send({ error: "deviceID and signKey required." });
                }
                const { deviceID, signKey } = parsed.data;

                const device = await this.db.retrieveDevice(deviceID);
                if (!device || device.signKey !== signKey) {
                    return res.status(404).send({ error: "Device not found." });
                }

                // Generate challenge nonce (32 bytes)
                const nonce = XUtils.encodeHex(xRandomBytes(32));
                const challengeID = crypto.randomUUID();
                this.deviceChallenges.set(challengeID, {
                    deviceID,
                    nonce,
                    time: Date.now(),
                });

                // Clean up expired challenges
                setTimeout(() => {
                    this.deviceChallenges.delete(challengeID);
                }, DEVICE_CHALLENGE_EXPIRY);

                this.log.info("Device challenge issued for " + deviceID);
                return res.send(
                    msgpack.encode({ challenge: nonce, challengeID }),
                );
            } catch (err: unknown) {
                this.log.error("Device challenge error: " + String(err));
                return res.sendStatus(500);
            }
        });

        this.api.post("/auth/device/verify", async (req, res) => {
            try {
                const parsed = deviceVerifyPayload.safeParse(req.body);
                if (!parsed.success) {
                    return res.status(400).send({
                        error: "challengeID and signed required.",
                    });
                }
                const { challengeID, signed } = parsed.data;

                const challenge = this.deviceChallenges.get(challengeID);
                if (!challenge) {
                    return res.status(401).send({
                        error: "Challenge expired or not found.",
                    });
                }

                // Consume the challenge (single-use)
                this.deviceChallenges.delete(challengeID);

                // Check expiry
                if (Date.now() - challenge.time > DEVICE_CHALLENGE_EXPIRY) {
                    return res
                        .status(401)
                        .send({ error: "Challenge expired." });
                }

                // Look up the device to get its public signKey
                const device = await this.db.retrieveDevice(challenge.deviceID);
                if (!device) {
                    return res.status(404).send({ error: "Device not found." });
                }

                // Verify the Ed25519 signature
                const opened = xSignOpen(
                    XUtils.decodeHex(signed),
                    XUtils.decodeHex(device.signKey),
                );
                if (!opened) {
                    return res
                        .status(401)
                        .send({ error: "Signature verification failed." });
                }

                // Verify the signed content matches the challenge nonce
                const signedNonce = XUtils.encodeHex(opened);
                if (signedNonce !== challenge.nonce) {
                    return res
                        .status(401)
                        .send({ error: "Challenge mismatch." });
                }

                // Look up device owner
                const user = await this.db.retrieveUser(device.owner);
                if (!user) {
                    return res
                        .status(404)
                        .send({ error: "Device owner not found." });
                }

                // Issue short-lived JWT (1 hour, not 7 days)
                const token = jwt.sign(
                    { user: censorUser(user) },
                    getJwtSecret(),
                    { expiresIn: DEVICE_AUTH_JWT_EXPIRY },
                );
                this.log.info(
                    "Device-key auth succeeded for " +
                        user.username +
                        " (device " +
                        device.deviceID +
                        ")",
                );
                return res.send(
                    msgpack.encode({ token, user: censorUser(user) }),
                );
            } catch (err: unknown) {
                this.log.error("Device verify error: " + String(err));
                return res.sendStatus(500);
            }
        });

        this.api.post("/mail", protect, async (req, res) => {
            const senderDeviceDetails = req.device;
            if (!senderDeviceDetails) {
                res.sendStatus(401);
                return;
            }
            const authorUserDetails = getUser(req);

            const parsed = mailPostPayload.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid mail payload",
                    issues: parsed.error.issues,
                });
                return;
            }
            const { header, mail } = parsed.data;

            try {
                await this.db.saveMail(
                    mail,
                    header,
                    senderDeviceDetails.deviceID,
                    authorUserDetails.userID,
                );
                this.log.info("Received mail for " + mail.recipient);

                const recipientDeviceDetails = await this.db.retrieveDevice(
                    mail.recipient,
                );
                if (!recipientDeviceDetails) {
                    res.sendStatus(400);
                    return;
                }

                res.sendStatus(200);
                this.notify(
                    recipientDeviceDetails.owner,
                    "mail",
                    crypto.randomUUID(),
                    null,
                    mail.recipient,
                );
            } catch (err: unknown) {
                this.log.error(String(err));
                res.status(500).send(String(err));
            }
        });

        this.api.post("/auth", async (req, res) => {
            const parsed = authPayload.safeParse(req.body);
            if (!parsed.success) {
                res.status(400).json({
                    error: "Invalid credentials format",
                });
                return;
            }
            const { password, username } = parsed.data;

            try {
                const userEntry = await this.db.retrieveUser(username);
                if (!userEntry) {
                    res.sendStatus(404);
                    this.log.warn("User does not exist.");
                    return;
                }

                const salt = XUtils.decodeHex(userEntry.passwordSalt);
                const payloadHash = XUtils.encodeHex(
                    hashPassword(password, salt),
                );

                if (payloadHash !== userEntry.passwordHash) {
                    res.sendStatus(401);
                    return;
                }

                const token = jwt.sign(
                    { user: censorUser(userEntry) },
                    getJwtSecret(),
                    { expiresIn: JWT_EXPIRY },
                );

                // just to make sure
                jwt.verify(token, getJwtSecret());

                res.send(
                    msgpack.encode({ token, user: censorUser(userEntry) }),
                );
            } catch (err: unknown) {
                this.log.error(String(err));
                res.sendStatus(500);
            }
        });

        this.api.post("/register", async (req, res) => {
            try {
                const regParsed = RegistrationPayloadSchema.safeParse(req.body);
                if (!regParsed.success) {
                    res.status(400).json({
                        error: "Invalid registration payload",
                        issues: regParsed.error.issues,
                    });
                    return;
                }
                const regPayload = regParsed.data;
                if (!usernameRegex.test(regPayload.username)) {
                    res.status(400).send({
                        error: "Username must be between three and nineteen letters, digits, or underscores.",
                    });
                    return;
                }

                const regKey = xSignOpen(
                    XUtils.decodeHex(regPayload.signed),
                    XUtils.decodeHex(regPayload.signKey),
                );

                if (
                    regKey &&
                    this.validateToken(
                        uuidStringify(regKey),
                        TokenScopes.Register,
                    )
                ) {
                    const [user, err] = await this.db.createUser(
                        regKey,
                        regPayload,
                    );
                    if (err !== null) {
                        const errCode =
                            "code" in err && typeof err.code === "string"
                                ? err.code
                                : undefined;
                        switch (errCode) {
                            case "ER_DUP_ENTRY":
                                const usernameConflict = String(err).includes(
                                    "users_username_unique",
                                );
                                const signKeyConflict = String(err).includes(
                                    "users_signkey_unique",
                                );

                                this.log.warn(
                                    "User attempted to register duplicate account.",
                                );
                                if (usernameConflict) {
                                    res.status(400).send({
                                        error: "Username is already registered.",
                                    });
                                    return;
                                }
                                if (signKeyConflict) {
                                    res.status(400).send({
                                        error: "Public key is already registered.",
                                    });
                                    return;
                                }
                                res.status(500).send({
                                    error: "An error occurred registering.",
                                });
                                break;
                            default:
                                this.log.info(
                                    "Unsupported sql error type: " +
                                        String(errCode),
                                );
                                this.log.error(String(err));
                                res.sendStatus(500);
                                break;
                        }
                    } else {
                        this.log.info("Registration success.");
                        if (!user) {
                            res.sendStatus(500);
                            return;
                        }
                        res.send(msgpack.encode(censorUser(user)));
                    }
                } else {
                    res.status(400).send({
                        error: "Invalid or no token supplied.",
                    });
                }
            } catch (err: unknown) {
                this.log.error("error registering user: " + String(err));
                res.sendStatus(500);
            }
        });

        this.server = this.api.listen(apiPort, () => {
            this.log.info("API started on port " + String(apiPort));
        });

        // Accept all WS upgrades — auth happens post-connection.
        this.server.on("upgrade", (req, socket, head) => {
            this.wss.handleUpgrade(req, socket, head, (ws) => {
                this.wss.emit("connection", ws);
            });
        });
    }

    private notify(
        userID: string,
        event: string,
        transmissionID: string,
        data?: unknown,
        deviceID?: string,
    ): void {
        for (const client of this.clients) {
            if (deviceID) {
                if (client.getDevice().deviceID === deviceID) {
                    const msg: NotifyMsg = {
                        data,
                        event,
                        transmissionID,
                        type: "notify",
                    };
                    client.send(msg);
                }
            } else {
                if (client.getUser().userID === userID) {
                    const msg: NotifyMsg = {
                        data,
                        event,
                        transmissionID,
                        type: "notify",
                    };
                    client.send(msg);
                }
            }
        }
    }

    private validateToken(key: string, scope: TokenScopes): boolean {
        this.log.info("Validating token: " + key);
        for (const rKey of this.actionTokens) {
            if (rKey.key === key) {
                if (rKey.scope !== scope) {
                    continue;
                }

                const age = Date.now() - new Date(rKey.time).getTime();
                this.log.info("Token found, " + String(age) + " ms old.");
                if (age < TOKEN_EXPIRY) {
                    this.log.info("Token is valid.");
                    this.deleteActionToken(rKey);
                    return true;
                } else {
                    this.log.info("Token is expired.");
                }
            }
        }
        this.log.info("Token not found.");
        return false;
    }
}
