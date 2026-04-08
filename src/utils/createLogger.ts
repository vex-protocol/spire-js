import winston from "winston";

/**
 * @ignore
 */
export function createLogger(logName: string, logLevel?: string) {
    const logger = winston.createLogger({
        defaultMeta: { service: "vex-" + logName },
        format: winston.format.combine(
            winston.format.timestamp({
                format: "YYYY-MM-DD HH:mm:ss",
            }),
            winston.format.errors({ stack: true }),
            winston.format.splat(),
            winston.format.json(),
        ),
        level: logLevel || "error",
        transports: [
            //
            // - Write all logs with level `error` and below to `error.log`
            // - Write all logs with level `info` and below to `combined.log`
            //
            new winston.transports.File({
                filename: "vex:" + logName + ".log",
                level: "error",
            }),
        ],
    });
    //
    // If we're not in production then log to the `console` with the format:
    // `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
    //
    if (
        process.env.NODE_ENV !== "production" &&
        process.env.NODE_ENV !== "test"
    ) {
        logger.add(
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple(),
                ),
            }),
        );
    }
    return logger;
}
