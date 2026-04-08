import type { IDevice, IFilePayload } from "@vex-chat/types";
import type { IUser } from "@vex-chat/types";
import type winston from "winston";

import { XUtils } from "@vex-chat/crypto";
import express from "express";
import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import multer from "multer";
import * as fs from "node:fs";

import type { Database } from "../Database.ts";

import { ALLOWED_IMAGE_TYPES, protect } from "./index.ts";

export const getAvatarRouter = (db: Database, log: winston.Logger) => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
        const filePath = "./avatars/" + req.params.userID;
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

    router.post("/:userID/json", protect, async (req, res) => {
        const payload: IFilePayload = req.body;
        const userDetails: IUser = (req as any).user;
        const deviceDetails: IDevice | undefined = (req as any).device;

        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        if (!payload.file) {
            console.warn("MISSING FILE");
            res.sendStatus(400);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));
        const mimeType = await fileTypeFromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                    mimeType?.ext,
            });
            return;
        }

        try {
            // write the file to disk
            fs.writeFile("avatars/" + userDetails.userID, buf, () => {
                log.info("Wrote new avatar " + userDetails.userID);
            });
            res.sendStatus(200);
        } catch (err) {
            log.warn(err);
            res.sendStatus(500);
        }
    });

    router.post(
        "/:userID",
        protect,
        multer().single("avatar"),
        async (req, res) => {
            const userDetails: IUser = (req as any).user;
            const deviceDetails: IDevice | undefined = (req as any).device;

            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            if (!req.file) {
                console.warn("MISSING FILE");
                res.sendStatus(400);
                return;
            }

            const mimeType = await fileTypeFromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                        mimeType?.ext,
                });
                return;
            }

            try {
                // write the file to disk
                fs.writeFile(
                    "avatars/" + userDetails.userID,
                    req.file.buffer,
                    () => {
                        log.info("Wrote new avatar " + userDetails.userID);
                    },
                );
                res.sendStatus(200);
            } catch (err) {
                log.warn(err);
                res.sendStatus(500);
            }
        },
    );

    return router;
};
