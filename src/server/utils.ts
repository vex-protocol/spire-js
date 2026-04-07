import type { IUser, IUserRecord } from "@vex-chat/types";

/**
 * Strips password fields from a DB user record, returning the
 * public-safe IUser shape.
 */
export const censorUser = (user: IUserRecord): IUser => {
    return {
        userID: user.userID,
        username: user.username,
        lastSeen: user.lastSeen,
    };
};
