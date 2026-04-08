import type { Database } from "../Database.ts";
import type { IDevice, IFilePayload, IFileSQL } from "@vex-chat/types";
import type winston from "winston";

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import * as path from "node:path";

import express from "express";

import { XUtils } from "@vex-chat/crypto";

import multer from "multer";

import { msgpack } from "../utils/msgpack.ts";

import { protect } from "./index.ts";

export const getFileRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:id", protect, async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            const stream = fs.createReadStream("./files/" + entry.fileID);
            stream.on("error", (err) => {
                log.error(err.toString());
                res.sendStatus(500);
            });
            stream.pipe(res);
        }
    });

    router.get("/:id/details", protect, async (req, res) => {
        const entry = await db.retrieveFile(req.params.id);
        if (!entry) {
            res.sendStatus(404);
        } else {
            fs.stat(path.resolve("./files/" + entry.fileID), (err, stat) => {
                if (err) {
                    res.sendStatus(500);
                    return;
                }
                res.set("Cache-control", "public, max-age=31536000");
                res.send(
                    msgpack.encode({
                        ...entry,
                        birthtime: stat.birthtime,
                        size: stat.size,
                    }),
                );
            });
        }
    });

    router.post("/json", protect, async (req, res) => {
        const deviceDetails: IDevice | undefined = (req as any).device;
        const payload: IFilePayload = req.body;

        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        if (payload.nonce === "") {
            res.sendStatus(400);
            return;
        }

        if (!payload.file) {
            res.sendStatus(400);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));

        const newFile: IFileSQL = {
            fileID: crypto.randomUUID(),
            nonce: payload.nonce,
            owner: payload.owner,
        };

        await fsp.writeFile("files/" + newFile.fileID, buf);
        log.info("Wrote new file " + newFile.fileID);

        await db.createFile(newFile);
        res.send(msgpack.encode(newFile));
    });

    router.post("/", protect, multer().single("file"), async (req, res) => {
        const deviceDetails: IDevice | undefined = (req as any).device;
        const payload: IFilePayload = req.body;

        if (!deviceDetails) {
            res.sendStatus(400);
            return;
        }

        if (req.file === undefined) {
            res.sendStatus(400);
            return;
        }

        if (payload.nonce === "") {
            res.sendStatus(400);
            return;
        }

        const newFile: IFileSQL = {
            fileID: crypto.randomUUID(),
            nonce: payload.nonce,
            owner: payload.owner,
        };

        await fsp.writeFile("files/" + newFile.fileID, req.file.buffer);
        log.info("Wrote new file " + newFile.fileID);

        await db.createFile(newFile);
        res.send(msgpack.encode(newFile));
    });

    return router;
};
