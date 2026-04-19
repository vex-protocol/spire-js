/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import { rmSync } from "node:fs";

rmSync("dist/__tests__", { force: true, recursive: true });
