/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { parse as uuidParse } from "uuid";

export function createUint8UUID(): Uint8Array {
    return uuidToUint8(crypto.randomUUID());
}

export function uuidToUint8(uuid: string): Uint8Array {
    return new Uint8Array(uuidParse(uuid));
}
