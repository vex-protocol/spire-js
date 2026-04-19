/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { Packr } from "msgpackr";

// Standard msgpack encoder/decoder configured for broad compatibility.
export const msgpack = new Packr({ moreTypes: false, useRecords: false });
