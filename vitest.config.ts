import { defineConfig } from "vitest/config";

export default defineConfig({
    test: {
        globals: true,
        include: [
            "**/__tests__/**/*.?(c|m)[jt]s?(x)",
            "**/*.{test,spec}.?(c|m)[jt]s?(x)",
        ],
    },
});
