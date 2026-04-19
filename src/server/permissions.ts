/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

import type { Permission } from "@vex-chat/types";

/**
 * Check whether any permission in the list covers the given resource
 * (any power level).
 */
export function hasAnyPermission(
    permissions: Permission[],
    resourceID: string,
): boolean {
    return permissions.some((p) => p.resourceID === resourceID);
}

/**
 * Check whether any permission in the list grants at least `minPowerLevel`
 * on the given resource.
 */
export function hasPermission(
    permissions: Permission[],
    resourceID: string,
    minPowerLevel: number,
): boolean {
    return permissions.some(
        (p) => p.resourceID === resourceID && p.powerLevel > minPowerLevel,
    );
}

/**
 * Check whether any permission in the list grants at least `minPowerLevel`
 * on the given resource AND belongs to the specified user.
 */
export function userHasPermission(
    permissions: Permission[],
    userID: string,
    minPowerLevel: number,
): boolean {
    return permissions.some(
        (p) => p.userID === userID && p.powerLevel > minPowerLevel,
    );
}
