import type { Database } from "./Database.ts";
import type {
    BaseMsg,
    ChallMsg,
    Device,
    ErrMsg,
    MailWS,
    ReceiptMsg,
    ResourceMsg,
    RespMsg,
    SuccessMsg,
    User,
    UserRecord,
} from "@vex-chat/types";
import type winston from "winston";
import type WebSocket from "ws";

import { EventEmitter } from "events";
import { setTimeout as sleep } from "node:timers/promises";

import { xConcat, XUtils } from "@vex-chat/crypto";
import { SocketAuthErrors } from "@vex-chat/types";

import pc from "picocolors";
import nacl from "tweetnacl";
import { parse as uuidParse, validate as uuidValidate } from "uuid";

import { type SpireOptions, TOKEN_EXPIRY } from "./Spire.ts";
import { createLogger } from "./utils/createLogger.ts";
import { createUint8UUID } from "./utils/createUint8UUID.ts";
import { msgpack } from "./utils/msgpack.ts";

export const POWER_LEVELS = {
    CREATE: 50,
    DELETE: 50,
    EMOJI: 25,
    INVITE: 25,
};

function emptyHeader() {
    return new Uint8Array(32);
}

const MAX_MSG_SIZE = 2048;

export class ClientManager extends EventEmitter {
    private alive: boolean = true;
    private authed: boolean = false;
    private challengeID: Uint8Array = createUint8UUID();
    private conn: WebSocket;
    private db: Database;
    private device: Device | null;
    private failed: boolean = false;
    private log: winston.Logger;
    private notify: (
        userID: string,
        event: string,
        transmissionID: string,
        data?: any,
        deviceID?: string,
    ) => void;
    private user: UserRecord | null;
    private userDetails: User;

    constructor(
        ws: WebSocket,
        db: Database,
        notify: (userID: string, event: string, transmissionID: string) => void,
        userDetails: User,
        options?: SpireOptions,
    ) {
        super();
        this.conn = ws;
        this.db = db;
        this.user = null;
        this.userDetails = userDetails;
        this.device = null;
        this.notify = notify;
        this.log = createLogger("client-manager", options?.logLevel || "error");

        this.initListeners();
        this.challenge();
    }

    public getDevice(): Device {
        return this.device!;
    }

    public getUser(): UserRecord {
        if (!this.authed) {
            throw new Error("You must be authed before getting user info.");
        }
        return this.user!;
    }

    public async send(msg: any, header?: Uint8Array) {
        if (header) {
            this.log.debug(pc.bold(pc.red("OUTH")), header.toString());
        } else {
            this.log.debug(pc.bold(pc.red("OUTH")), emptyHeader.toString());
        }

        const packedMessage = packMessage(msg, header);

        this.log.info(
            pc.bold("⟶   ") +
                responseColor(msg.type.toUpperCase()) +
                " " +
                this.toString() +
                " " +
                pc.yellow(Buffer.byteLength(packedMessage)),
        );

        this.log.debug(pc.bold(pc.red("OUT")), msg);
        try {
            this.conn.send(packedMessage);
        } catch (err) {
            this.log.warn(err.toString());
            this.fail();
        }
    }

    public override toString() {
        if (!this.user || !this.device) {
            return "Unauthorized#0000";
        }
        return this.user.username + "<" + this.getDevice().deviceID + ">";
    }

    private authorize(transmissionID: string) {
        this.authed = true;
        this.sendAuthedMessage(transmissionID);
        this.db.markDeviceLogin(this.getDevice());
        this.emit("authed");
    }

    private challenge() {
        this.challengeID = new Uint8Array(uuidParse(crypto.randomUUID()));
        const challenge: ChallMsg = {
            challenge: this.challengeID,
            transmissionID: crypto.randomUUID(),
            type: "challenge",
        };
        this.send(challenge);
    }

    private fail() {
        if (this.failed) {
            return;
        }
        if (this.conn) {
            this.log.warn("Connection closed.");
            this.conn.close();
        }
        this.failed = true;
        this.emit("fail");
    }

    private async handleReceipt(msg: ReceiptMsg) {
        await this.db.deleteMail(msg.nonce, this.getDevice().deviceID);
    }

    private initListeners() {
        this.conn.on("open", () => {
            setTimeout(() => {
                if (!this.authed) {
                    this.conn.close();
                }
            }, TOKEN_EXPIRY);
            this.pingLoop();
        });
        this.conn.on("close", () => {
            this.fail();
        });
        this.conn.on("message", (message: Buffer) => {
            const [header, msg] = unpackMessage(message);
            const size = Buffer.byteLength(message);

            if (size > MAX_MSG_SIZE) {
                this.sendErr(
                    msg.transmissionID,
                    "Message is too big. Received size " +
                        size +
                        " while max size is " +
                        MAX_MSG_SIZE,
                );
                return;
            }

            this.log.info(
                pc.bold("⟵   ") +
                    (msg.type === "resource"
                        ? crudColor(
                              (msg as ResourceMsg).action.toUpperCase(),
                          ) +
                          " " +
                          pc.bold(
                              (msg as ResourceMsg).resourceType.toUpperCase(),
                          )
                        : pc.bold(msg.type.toUpperCase())) +
                    " " +
                    this.toString() +
                    " " +
                    pc.yellow(size),
            );
            this.log.debug(pc.bold(pc.red("INH")), header.toString());
            this.log.debug(pc.bold(pc.red("IN")), msg);

            if (!msg.type) {
                this.sendErr(msg.transmissionID, "Message type is required.");
                return;
            }

            if (!uuidValidate(msg.transmissionID)) {
                this.sendErr(
                    crypto.randomUUID(),
                    "transmissionID is required and must be a valid uuid.",
                );
                return;
            }

            switch (msg.type) {
                case "ping":
                    this.pong(msg.transmissionID);
                    break;
                case "pong":
                    this.setAlive(true);
                    break;
                case "receipt":
                    this.handleReceipt(msg as ReceiptMsg);
                    break;
                case "resource":
                    if (!this.authed) {
                        this.sendErr(
                            msg.transmissionID,
                            "You are not authenticated.",
                        );
                        break;
                    }
                    this.parseResourceMsg(msg as ResourceMsg, header);
                    break;
                case "response":
                    this.verifyResponse(msg as RespMsg);
                    break;
                default:
                    this.log.info("unsupported message %s", msg.type);
                    break;
            }
        });
    }

    private async parseResourceMsg(msg: ResourceMsg, header: Uint8Array) {
        switch (msg.resourceType) {
            case "mail":
                if (msg.action === "CREATE") {
                    const mail: MailWS = msg.data;

                    try {
                        await this.db.saveMail(
                            mail,
                            header,
                            this.getDevice().deviceID,
                            this.getUser().userID,
                        );
                        this.log.info(
                            "Received mail for " + msg.data.recipient,
                        );

                        const deviceDetails = await this.db.retrieveDevice(
                            msg.data.recipient,
                        );
                        if (!deviceDetails) {
                            this.sendErr(
                                msg.transmissionID,
                                "No associated user record found for device.",
                            );
                            return;
                        }

                        this.sendSuccess(msg.transmissionID, null);
                        this.notify(
                            deviceDetails.owner,
                            "mail",
                            msg.transmissionID,
                            null,
                            msg.data.recipient,
                        );
                    } catch (err) {
                        this.log.error(err);
                        this.sendErr(msg.transmissionID, err.toString());
                    }
                }
                break;
            default:
                this.log.info("Unsupported resource type " + msg.resourceType);
        }
    }

    private ping() {
        if (!this.alive) {
            this.fail();
            return;
        }
        this.setAlive(false);
        const p = { transmissionID: crypto.randomUUID(), type: "ping" };
        this.send(p);
    }

    private async pingLoop() {
        while (true) {
            this.ping();
            await sleep(5000);
        }
    }

    private pong(transmissionID: string) {
        // ping is allowed before auth
        if (this.user) {
            this.db.markUserSeen(this.user);
        }

        const p = { transmissionID, type: "pong" };
        this.send(p);
    }

    private sendAuthedMessage(transmissionID: string) {
        this.send({ transmissionID, type: "authorized" });
    }

    private sendAuthError(error: SocketAuthErrors) {
        this.send({ error, type: "authErr" });
    }

    private sendErr(transmissionID: string, message: string, data?: any) {
        const error: ErrMsg = {
            data,
            error: message,
            transmissionID,
            type: "error",
        };
        this.send(error);
    }

    private sendSuccess(
        transmissionID: string,
        data: any,
        header?: Uint8Array,
        timestamp?: string,
    ) {
        const msg: SuccessMsg = {
            data,
            timestamp,
            transmissionID,
            type: "success",
        };
        this.send(msg, header);
    }

    private setAlive(status: boolean) {
        this.alive = status;
    }

    private async verifyResponse(msg: RespMsg) {
        const user = await this.db.retrieveUser(this.userDetails.userID);
        if (user) {
            const devices = await this.db.retrieveUserDeviceList([user.userID]);
            let message: null | Uint8Array = null;
            for (const device of devices) {
                const verified = nacl.sign.open(
                    msg.signed,
                    XUtils.decodeHex(device.signKey),
                );
                if (verified) {
                    message = verified;
                    this.device = device;
                }
            }
            if (!message) {
                this.log.warn("Signature verification failed!");
                this.sendAuthError(SocketAuthErrors.BadSignature);
                this.fail();
                return;
            }

            if (XUtils.bytesEqual(this.challengeID, message)) {
                this.user = user;
                this.authorize(msg.transmissionID);
            } else {
                this.log.warn("Token is bad!");
                this.sendAuthError(SocketAuthErrors.InvalidToken);
            }
        } else {
            this.log.info("User is not registered.");
            this.sendAuthError(SocketAuthErrors.UserNotRegistered);

            this.fail();
        }
    }
}

function packMessage(msg: any, header?: Uint8Array) {
    const msgb = Uint8Array.from(msgpack.encode(msg));
    const msgh = header || emptyHeader();
    return xConcat(msgh, msgb);
}

function unpackMessage(msg: Buffer): [Uint8Array, BaseMsg] {
    const msgp = Uint8Array.from(msg);

    const msgh = msgp.slice(0, 32);
    const msgb: BaseMsg = msgpack.decode(msgp.slice(32));

    return [msgh, msgb];
}

const crudColor = (action: string): string => {
    switch (action) {
        case "CREATE":
            return pc.bold(pc.yellow(action));
        case "DELETE":
            return pc.bold(pc.red(action));
        case "RETRIEVE":
            return pc.bold(pc.yellow(action));
        case "UPDATE":
            return pc.bold(pc.cyan(action));
        default:
            return action;
    }
};

const responseColor = (status: string): string => {
    switch (status) {
        case "ERROR":
            return pc.bold(pc.red(status));
        case "SUCCESS":
            return pc.bold(pc.green(status));
        default:
            return status;
    }
};
