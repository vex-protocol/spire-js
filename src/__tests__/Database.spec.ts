/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { SpireOptions } from "../Spire.ts";
import type { PreKeysWS } from "@vex-chat/types";

import { XUtils } from "@vex-chat/crypto";

import * as uuid from "uuid";
import { describe, expect, it, vi } from "vitest";

import { Database } from "../Database.ts";

// vi.mock is hoisted above all imports automatically.
// Minimal stubs for uuid functions used by spire src: v4, parse, stringify.
vi.mock("uuid", () => ({
    parse: (s: string) => {
        const matches = s.replace(/-/g, "").match(/.{2}/g);
        if (!matches) throw new Error("Invalid UUID");
        return Uint8Array.from(matches.map((b) => parseInt(b, 16)));
    },
    stringify: (b: Uint8Array) => {
        const hex = Array.from(b)
            .map((x) => x.toString(16).padStart(2, "0"))
            .join("");
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    },
    v4: vi.fn(() => "93ce482b-a0f2-4f6e-b1df-3aed61073552"),
    validate: () => true,
}));

describe("Database", () => {
    // Reusable test data
    const keyID = "de459e05-aa63-4dfa-97b4-ed43d5c7a5f7";
    const userID = "4e67b90f-cbf8-44bc-8ce3-d3b248f033f1";
    const deviceID = "23cb0b27-7d0c-43b2-87e1-c2b93e0095e5";

    const publicKey = XUtils.decodeHex(
        "30c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
    );
    const signature = XUtils.decodeHex(
        "dd0665079426c3efcf4dce9b1487e4aca132f8147581b3294c3f23ddd2b4ba8240a10082bd06805d7eb320d91af971da3306e11b60073ccc3d829710f5036004000030c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
    );

    const testSQLPreKey = {
        deviceID,
        index: 1,
        keyID,
        publicKey:
            "30c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
        signature:
            "dd0665079426c3efcf4dce9b1487e4aca132f8147581b3294c3f23ddd2b4ba8240a10082bd06805d7eb320d91af971da3306e11b60073ccc3d829710f5036004000030c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
        userID,
    };

    const testWSPreKey: PreKeysWS = {
        deviceID,
        index: 1,
        publicKey,
        signature,
    };

    const options: SpireOptions = {
        dbType: "sqlite3mem",
    };

    describe("saveOTK", () => {
        it("takes a userId and one time key, adds a keyId and saves it to oneTimeKey table", async () => {
            expect.assertions(1);

            vi.mocked(uuid.v4).mockReturnValueOnce(keyID);

            const provider = new Database(options);
            await new Promise<void>((resolve, reject) => {
                provider.once("ready", () => {
                    void (async () => {
                        try {
                            await provider.saveOTK(
                                testSQLPreKey.userID,
                                testSQLPreKey.deviceID,
                                [
                                    {
                                        deviceID,
                                        index: 1,
                                        publicKey,
                                        signature,
                                    },
                                ],
                            );
                            const oneTimeKey = await provider.getOTK(deviceID);
                            expect(oneTimeKey).toEqual(testWSPreKey);
                            await provider.close();
                            resolve();
                        } catch (e: unknown) {
                            reject(
                                e instanceof Error ? e : new Error(String(e)),
                            );
                        }
                    })();
                });
            });
        });
    });

    describe("getPreKeys", () => {
        it("returns a preKey by deviceID if said preKey exists.", async () => {
            expect.assertions(1);

            const provider = new Database(options);
            await new Promise<void>((resolve, reject) => {
                provider.once("ready", () => {
                    void (async () => {
                        try {
                            await provider["db"]
                                .insertInto("preKeys")
                                .values(testSQLPreKey)
                                .execute();
                            const result = await provider.getPreKeys(deviceID);
                            expect(result).toEqual(testWSPreKey);
                            await provider.close();
                            resolve();
                        } catch (e: unknown) {
                            reject(
                                e instanceof Error ? e : new Error(String(e)),
                            );
                        }
                    })();
                });
            });
        });

        it("return null if there are no preKeys with deviceID param", async () => {
            expect.assertions(1);
            const provider = new Database(options);
            await new Promise<void>((resolve, reject) => {
                provider.once("ready", () => {
                    void (async () => {
                        try {
                            const result = await provider.getPreKeys(deviceID);
                            expect(result).toBeNull();
                            await provider.close();
                            resolve();
                        } catch (e: unknown) {
                            reject(
                                e instanceof Error ? e : new Error(String(e)),
                            );
                        }
                    })();
                });
            });
        });
    });
});
