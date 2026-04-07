// tslint:disable: no-string-literal

import { vi, describe, it, expect } from "vitest";
import { XUtils } from "@vex-chat/crypto";
import type { IPreKeysSQL, IPreKeysWS } from "@vex-chat/types";
import * as uuid from "uuid";
import winston from "winston";

import { Database } from "../Database.ts";
import type { ISpireOptions } from "../Spire.ts";

// vi.mock is hoisted above all imports automatically.
// Minimal stubs for uuid functions used by spire src: v4, parse, stringify.
vi.mock("uuid", () => ({
    v4: vi.fn(() => "93ce482b-a0f2-4f6e-b1df-3aed61073552"),
    parse: (s: string) =>
        Uint8Array.from(
            s
                .replace(/-/g, "")
                .match(/.{2}/g)!
                .map((b) => parseInt(b, 16)),
        ),
    stringify: (b: Uint8Array) => {
        const hex = Array.from(b)
            .map((x) => x.toString(16).padStart(2, "0"))
            .join("");
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    },
    validate: () => true,
}));

/** Winston logger stub — Database.close() calls `.info`, and `{}` breaks that. */
function silentLogger(): winston.Logger {
    const noop = vi.fn();
    return {
        log: noop,
        info: noop,
        warn: noop,
        error: noop,
        debug: noop,
        verbose: noop,
    } as unknown as winston.Logger;
}

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

    const testSQLPreKey: IPreKeysSQL = {
        userID,
        keyID,
        deviceID,
        publicKey:
            "30c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
        signature:
            "dd0665079426c3efcf4dce9b1487e4aca132f8147581b3294c3f23ddd2b4ba8240a10082bd06805d7eb320d91af971da3306e11b60073ccc3d829710f5036004000030c2d0294c1cfdbb73c6b3bbe6010088c2dba8384b04ff2e2b92172431d66b5e",
        index: 1,
    };

    const testWSPreKey: IPreKeysWS = {
        publicKey,
        signature,
        deviceID,
        index: 1,
    };

    const options: ISpireOptions = {
        dbType: "sqlite3mem",
    };

    describe("saveOTK", () => {
        it("takes a userId and one time key, adds a keyId and saves it to oneTimeKey table", async () => {
            expect.assertions(1);

            vi.mocked(uuid.v4).mockReturnValueOnce(keyID);
            vi.spyOn(winston, "createLogger").mockReturnValueOnce(
                silentLogger(),
            );

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
                                        publicKey,
                                        signature,
                                        index: 1,
                                        deviceID,
                                    },
                                ],
                            );
                            const oneTimeKey = await provider.getOTK(deviceID);
                            expect(oneTimeKey).toEqual(testWSPreKey);
                            await provider.close();
                            resolve();
                        } catch (e) {
                            reject(e);
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
                        } catch (e) {
                            reject(e);
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
                        } catch (e) {
                            reject(e);
                        }
                    })();
                });
            });
        });
    });
});
