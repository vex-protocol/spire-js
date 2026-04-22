#!/usr/bin/env node
/**
 * Rebuild libvex-js and write `npm pack` output to `vendor/vex-chat-libvex-*.tgz`
 * (path is defined by libvex's package version). Run from the spire-js repo root.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const spireRoot = dirname(scriptDir);
const libvexRoot = join(spireRoot, "..", "libvex-js");
const vendorDir = join(spireRoot, "vendor");

execFileSync("npm", ["run", "build"], { cwd: libvexRoot, stdio: "inherit" });
execFileSync("npm", ["pack", "--pack-destination", vendorDir], {
    cwd: libvexRoot,
    stdio: "inherit",
});
