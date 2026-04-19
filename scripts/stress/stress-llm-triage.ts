/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Send last fatal issue bundle (+ optional repo manifest) to an OpenAI-compatible
 * chat endpoint. The model is instructed to only use supplied JSON facts—no
 * invented root causes.
 *
 * Env:
 *   SPIRE_STRESS_LLM_URL      — full URL to POST JSON (default http://127.0.0.1:1234/v1/chat/completions)
 *   SPIRE_STRESS_LLM_API_KEY  — optional Bearer token
 *   SPIRE_STRESS_LLM_MODEL    — optional override; if unset, first model from GET …/v1/models (LM Studio)
 *   SPIRE_STRESS_LLM_FULL=1   — include full manifest/docsPack and long JSON (CLI issue triage). Omit for default slim facet payloads.
 *   STRESS_ISSUE_BUNDLE_PATH  — override bundle path (default ~/.spire-stress/last-issue-bundle.json)
 *   STRESS_MANIFEST_PATH      — optional repo-manifest.json to include (trimmed)
 *   STRESS_DOCS_PACK_PATH     — optional docs-pack.json from `npm run stress:docs-pack` (trimmed)
 *
 * @example
 *   SPIRE_STRESS_LLM_URL=http://127.0.0.1:8080/v1/chat/completions SPIRE_STRESS_LLM_MODEL=llama3 npm run stress:llm-triage
 */
import {
    loadDocsPackFromEnv,
    loadIssueBundleFromEnv,
    loadManifestFromEnv,
    runLlmTriage,
} from "./stress-llm-triage-core.ts";

async function main(): Promise<void> {
    const bundle = loadIssueBundleFromEnv();
    const manifest = loadManifestFromEnv();
    const docsPack = loadDocsPackFromEnv();

    const result = await runLlmTriage({ bundle, docsPack, manifest });
    if (!result.ok) {
        process.stderr.write(result.message);
        process.stderr.write("\n");
        if (result.detail !== undefined) {
            process.stderr.write(`${result.detail}\n`);
        }
        process.exit(1);
    }

    process.stdout.write(result.markdown);
    process.stdout.write("\n");
}

void main().catch((e: unknown) => {
    process.stderr.write(e instanceof Error ? e.message : String(e));
    process.stderr.write("\n");
    process.exit(1);
});
