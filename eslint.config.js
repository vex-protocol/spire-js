import vitest from "@vitest/eslint-plugin";
import n from "eslint-plugin-n";
import perfectionist from "eslint-plugin-perfectionist";
import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier/flat";

export default tseslint.config(
    ...tseslint.configs.strictTypeChecked,
    n.configs["flat/recommended"],
    perfectionist.configs["recommended-natural"],
    {
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            "@typescript-eslint/no-explicit-any": "error",
            "@typescript-eslint/no-unsafe-assignment": "error",
            "@typescript-eslint/no-unsafe-member-access": "error",
            "@typescript-eslint/no-unsafe-argument": "error",
            "@typescript-eslint/no-unsafe-call": "error",
            "@typescript-eslint/no-unsafe-type-assertion": "error",
            "@typescript-eslint/no-unsafe-return": "error",
            "@typescript-eslint/no-floating-promises": "error",
            "@typescript-eslint/require-await": "error",
            "@typescript-eslint/restrict-plus-operands": "error",
            "@typescript-eslint/no-misused-promises": "error",
            "@typescript-eslint/no-unused-vars": [
                "error",
                {
                    argsIgnorePattern: "^_",
                    caughtErrorsIgnorePattern: "^_",
                    varsIgnorePattern: "^_",
                },
            ],
            "@typescript-eslint/prefer-promise-reject-errors": "error",
            "@typescript-eslint/no-unnecessary-type-assertion": "error",

            "@typescript-eslint/consistent-type-imports": [
                "error",
                {
                    prefer: "type-imports",
                    fixStyle: "separate-type-imports",
                },
            ],
            "@typescript-eslint/consistent-type-exports": "error",
            "@typescript-eslint/no-import-type-side-effects": "error",

            "perfectionist/sort-imports": [
                "error",
                {
                    type: "natural",
                    order: "asc",
                    ignoreCase: true,
                    internalPattern: ["^@vex-chat/"],
                    newlinesBetween: 1,
                    customGroups: [
                        {
                            groupName: "type-imports",
                            modifiers: ["type"],
                        },
                        {
                            groupName: "framework",
                            elementNamePattern: "^express",
                        },
                    ],
                    groups: [
                        "type-imports",
                        "builtin",
                        "framework",
                        "internal",
                        "external",
                        "parent",
                        "sibling",
                        "index",
                        "unknown",
                    ],
                },
            ],

            "n/no-missing-import": "off",
            "n/no-unpublished-import": "off",
            "n/no-process-exit": "off",
        },
    },
    {
        files: ["src/__tests__/**/*.ts"],
        plugins: { vitest },
        rules: {
            ...vitest.configs.recommended.rules,
            "@typescript-eslint/no-explicit-any": "off",
            "@typescript-eslint/no-unsafe-assignment": "off",
            "@typescript-eslint/no-unsafe-member-access": "off",
            "@typescript-eslint/no-unsafe-call": "off",
            "@typescript-eslint/no-unsafe-argument": "off",
            "@typescript-eslint/no-unsafe-type-assertion": "off",
            "@typescript-eslint/no-non-null-assertion": "off",
            "@typescript-eslint/prefer-promise-reject-errors": "off",
            "@typescript-eslint/no-unused-vars": "warn",
        },
    },
    eslintConfigPrettier,
);
