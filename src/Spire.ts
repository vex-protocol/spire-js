import type {
    ActionToken,
    BaseMsg,
    Device,
    MailWS,
    NotifyMsg,
    RegistrationPayload,
    User,
} from "@vex-chat/types";
import type { Server } from "http";
import type winston from "winston";

import { EventEmitter } from "events";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import { TokenScopes } from "@vex-chat/types";

import jwt from "jsonwebtoken";
import nacl from "tweetnacl";
import { stringify as uuidStringify } from "uuid";
import { WebSocketServer } from "ws";

import { ClientManager } from "./ClientManager.ts";
import { Database, hashPassword } from "./Database.ts";
import { initApp, protect } from "./server/index.ts";
import { censorUser } from "./server/utils.ts";
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
        const pkg = JSON.parse(raw) as { version?: string };
        return pkg.version || "unknown";
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
    private signKeys: nacl.SignKeyPair;

    private readonly startedAt = new Date();
    private readonly version = getAppVersion();
    private wss: WebSocketServer = new WebSocketServer({ noServer: true });

    constructor(SK: string, options?: SpireOptions) {
        super();
        this.signKeys = nacl.sign.keyPair.fromSecretKey(XUtils.decodeHex(SK));

        this.db = new Database(options);
        this.db.on("ready", () => {
            this.dbReady = true;
            this.bootstrapRequestCounter().catch((err) => {
                this.log.error(
                    "Failed to load persisted request counter: " + err,
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
                this.db.incrementRequestsTotal(1).catch((err) => {
                    this.log.warn(
                        "Failed to persist request counter increment: " + err,
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
                    : Buffer.from(data as ArrayBuffer).toString();
                clearTimeout(timer);
                ws.off("message", onFirstMessage);

                try {
                    const parsed = JSON.parse(str);
                    if (parsed.type !== "auth" || !parsed.token) {
                        throw new Error(
                            "Expected { type: 'auth', token }, got type=" +
                                parsed.type,
                        );
                    }
                    const result = jwt.verify(parsed.token, getJwtSecret());
                    const userDetails: User = (result as any).user;

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
                                this.clients.length,
                        );
                    });

                    client.on("authed", () => {
                        this.log.info(
                            "New client authorized: " + client.toString(),
                        );
                        this.clients.push(client);
                        this.log.info(
                            "Current authorized clients: " +
                                this.clients.length,
                        );
                    });
                } catch (err) {
                    this.log.warn("WS auth failed: " + err);
                    const errMsg: BaseMsg = {
                        transmissionID: crypto.randomUUID(),
                        type: "unauthorized",
                    };
                    ws.send(XUtils.packMessage(errMsg));
                    ws.close();
                }
            };

            ws.on("message", onFirstMessage);
            ws.on("close", () => clearTimeout(timer));
        });

        this.api.get(
            "/token/:tokenType",
            (req, res, next) => {
                if (req.params.tokenType !== "register") {
                    protect(req, res, next);
                } else {
                    next();
                }
            },
            async (req, res) => {
                const allowedTokens = [
                    "file",
                    "register",
                    "avatar",
                    "device",
                    "invite",
                    "emoji",
                    "connect",
                ];

                const { tokenType } = req.params;

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
                } catch (err) {
                    console.error(err.toString());
                    return res.sendStatus(500);
                }
            },
        );

        this.api.post("/whoami", async (req, res) => {
            if (!(req as any).user) {
                res.sendStatus(401);
                return;
            }

            res.send(
                msgpack.encode({
                    exp: (req as any).exp,
                    token: (req as any).bearerToken,
                    user: (req as any).user,
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

        this.api.post("/goodbye", protect, async (req, res) => {
            const token = jwt.sign(
                { user: censorUser((req as any).user) },
                getJwtSecret(),
                { expiresIn: -1 },
            );
            res.sendStatus(200);
        });

        // ── Device-key auth ──────────────────────────────────────────

        this.api.post("/auth/device", async (req, res) => {
            try {
                const { deviceID, signKey } = req.body as {
                    deviceID: string;
                    signKey: string;
                };
                if (!deviceID || !signKey) {
                    return res
                        .status(400)
                        .send({ error: "deviceID and signKey required." });
                }

                const device = await this.db.retrieveDevice(deviceID);
                if (!device || device.signKey !== signKey) {
                    return res.status(404).send({ error: "Device not found." });
                }

                // Generate challenge nonce (32 bytes)
                const nonce = XUtils.encodeHex(nacl.randomBytes(32));
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
            } catch (err) {
                this.log.error("Device challenge error: " + err);
                return res.sendStatus(500);
            }
        });

        this.api.post("/auth/device/verify", async (req, res) => {
            try {
                const { challengeID, signed } = req.body as {
                    challengeID: string;
                    signed: string;
                };
                if (!challengeID || !signed) {
                    return res.status(400).send({
                        error: "challengeID and signed required.",
                    });
                }

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
                const opened = nacl.sign.open(
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
            } catch (err) {
                this.log.error("Device verify error: " + err);
                return res.sendStatus(500);
            }
        });

        this.api.post("/mail", protect, async (req, res) => {
            const senderDeviceDetails: Device | undefined = (req as any)
                .device;
            if (!senderDeviceDetails) {
                res.sendStatus(401);
                return;
            }
            const authorUserDetails: User = (req as any).user;

            const { header, mail }: { header: Uint8Array; mail: MailWS } =
                req.body;

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
            } catch (err) {
                this.log.error(err);
                res.status(500).send(err.toString());
            }
        });

        this.api.post("/auth", async (req, res) => {
            const credentials: { password: string; username: string; } =
                req.body;

            if (typeof credentials.password !== "string") {
                res.status(400).send(
                    "Password is required and must be a string.",
                );
                return;
            }

            if (typeof credentials.username !== "string") {
                res.status(400).send(
                    "Username is required and must be a string.",
                );
                return;
            }

            try {
                const userEntry = await this.db.retrieveUser(
                    credentials.username,
                );
                if (!userEntry) {
                    res.sendStatus(404);
                    this.log.warn("User does not exist.");
                    return;
                }

                const salt = XUtils.decodeHex(userEntry.passwordSalt);
                const payloadHash = XUtils.encodeHex(
                    hashPassword(credentials.password, salt),
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
            } catch (err) {
                this.log.error(err.toString());
                res.sendStatus(500);
            }
        });

        this.api.post("/register", async (req, res) => {
            try {
                const regPayload: RegistrationPayload = req.body;
                if (!usernameRegex.test(regPayload.username)) {
                    res.status(400).send({
                        error: "Username must be between three and nineteen letters, digits, or underscores.",
                    });
                    return;
                }

                const regKey = nacl.sign.open(
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
                        switch ((err as any).code) {
                            case "ER_DUP_ENTRY":
                                const usernameConflict = err
                                    .toString()
                                    .includes("users_username_unique");
                                const signKeyConflict = err
                                    .toString()
                                    .includes("users_signkey_unique");

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
                                        (err as any).code,
                                );
                                this.log.error(err);
                                res.sendStatus(500);
                                break;
                        }
                    } else {
                        this.log.info("Registration success.");
                        res.send(msgpack.encode(censorUser(user!)));
                    }
                } else {
                    res.status(400).send({
                        error: "Invalid or no token supplied.",
                    });
                }
            } catch (err) {
                this.log.error("error registering user: " + err.toString());
                res.sendStatus(500);
            }
        });

        this.server = this.api.listen(apiPort, () => {
            this.log.info("API started on port " + apiPort.toString());
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
        data?: any,
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

                const age =
                    Date.now() - new Date(rKey.time).getTime();
                this.log.info("Token found, " + age + " ms old.");
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
