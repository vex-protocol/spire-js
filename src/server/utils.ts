import type { UserRecord, User } from "@vex-chat/types";

/**
 * Strips password fields from a DB user record, returning the
 * public-safe User shape.
 */
export const censorUser = (user: UserRecord): User => {
    return {
        lastSeen: user.lastSeen,
        userID: user.userID,
        username: user.username,
    };
};
