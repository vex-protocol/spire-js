/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";

import express from "express";

import { XUtils } from "@vex-chat/crypto";
import { FilePayloadSchema } from "@vex-chat/types";

import { fileTypeFromBuffer, fileTypeFromFile } from "file-type";
import multer from "multer";
import { z } from "zod/v4";

import { uploadLimiter } from "./rateLimit.ts";
import { getParam, getUser } from "./utils.ts";

import { ALLOWED_IMAGE_TYPES, protect } from "./index.ts";

const safePathParam = z.string().regex(/^[a-zA-Z0-9._-]+$/);

export const getAvatarRouter = () => {
    const router = express.Router();

    router.get("/:userID", async (req, res) => {
        const safeId = safePathParam.safeParse(getParam(req, "userID"));
        if (!safeId.success) {
            res.sendStatus(400);
            return;
        }
        const filePath = "./avatars/" + safeId.data;
        const typeDetails = await fileTypeFromFile(filePath).catch(() => null);
        if (!typeDetails) {
            res.sendStatus(404);
            return;
        }
        res.set("Content-type", typeDetails.mime);
        res.set("Cache-control", "public, max-age=31536000");

        const stream = fs.createReadStream(filePath);
        stream.on("error", (_err) => {
            // debugger: avatar stream read error
            res.sendStatus(500);
        });
        stream.pipe(res);
    });

    router.post("/:userID/json", protect, async (req, res) => {
        const parsed = FilePayloadSchema.safeParse(req.body);
        if (!parsed.success) {
            res.status(400).json({
                error: "Invalid file payload",
                issues: parsed.error.issues,
            });
            return;
        }
        const payload = parsed.data;
        const userDetails = getUser(req);
        const deviceDetails = req.device;

        if (!deviceDetails) {
            res.sendStatus(401);
            return;
        }

        if (!payload.file) {
            res.sendStatus(400);
            return;
        }

        const buf = Buffer.from(XUtils.decodeBase64(payload.file));
        const mimeType = await fileTypeFromBuffer(buf);
        if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
            res.status(400).send({
                error:
                    "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                    String(mimeType?.ext),
            });
            return;
        }

        try {
            // write the file to disk
            await fsp.writeFile("avatars/" + userDetails.userID, buf);
            res.sendStatus(200);
        } catch (_err: unknown) {
            // debugger: avatar write failed
            res.sendStatus(500);
        }
    });

    router.post(
        "/:userID",
        uploadLimiter,
        protect,
        multer().single("avatar"),
        async (req, res) => {
            const userDetails = getUser(req);
            const deviceDetails = req.device;

            if (!deviceDetails) {
                res.sendStatus(401);
                return;
            }

            if (!req.file) {
                res.sendStatus(400);
                return;
            }

            const mimeType = await fileTypeFromBuffer(req.file.buffer);
            if (!ALLOWED_IMAGE_TYPES.includes(mimeType?.mime || "no/type")) {
                res.status(400).send({
                    error:
                        "Unsupported file type. Expected jpeg, png, gif, apng, avif, or svg but received " +
                        String(mimeType?.ext),
                });
                return;
            }

            try {
                // write the file to disk
                await fsp.writeFile(
                    "avatars/" + userDetails.userID,
                    req.file.buffer,
                );
                res.sendStatus(200);
            } catch (_err: unknown) {
                // debugger: avatar write failed
                res.sendStatus(500);
            }
        },
    );

    return router;
};
