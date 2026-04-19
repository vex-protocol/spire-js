/**
 * Copyright (c) 2020-2026 Vex Heavy Industries LLC
 * Licensed under AGPL-3.0. See LICENSE for details.
 * Commercial licenses available at vex.wtf
 */

/**
 * Shared LLM triage: load attachments, build payloads, POST to OpenAI-compatible API.
 * Used by the CLI (`stress-llm-triage.ts`) and optional offline triage flows.
 */
import { existsSync, readFileSync } from "node:fs";

import axios from "axios";

import { STRESS_ISSUE_BUNDLE_PATH } from "./stress-issue-bundle.ts";
import {
    firstClientProtocolCall,
    formatHarnessCallNotation,
} from "./stress-request-context.ts";

export { firstClientProtocolCall, formatHarnessCallNotation };

export const STRESS_LLM_TRIAGE_DEFAULT_URL =
    "http://127.0.0.1:1234/v1/chat/completions";

/**
 * Auto **full** LLM triage (long markdown) on the stress dashboard — opt-in only.
 * Set `SPIRE_STRESS_LLM_AUTO=1` to re-enable the old always-on behaviour.
 */
export function isStressLlmFullAutoEnabled(): boolean {
    const v = process.env["SPIRE_STRESS_LLM_AUTO"]?.trim().toLowerCase() ?? "";
    return v === "1" || v === "true" || v === "on" || v === "yes";
}

/** @deprecated Use {@link isStressLlmFullAutoEnabled}. Kept for grep compatibility. */
export function isStressLlmAutoEnabled(): boolean {
    return isStressLlmFullAutoEnabled();
}

/**
 * Auto short **TITLE:** lines for issue rows — on by default when an LLM URL is used.
 * Set `SPIRE_STRESS_LLM_TITLE_AUTO=0` to use heuristics only.
 */
export function isStressLlmTitleAutoEnabled(): boolean {
    const v =
        process.env["SPIRE_STRESS_LLM_TITLE_AUTO"]?.trim().toLowerCase() ?? "";
    if (v === "0" || v === "false" || v === "off" || v === "no") {
        return false;
    }
    return true;
}

export const LIVE_TRIAGE_SCHEMA = "spire-stress-live-triage@1";

/** Narrow bundle for one deduplicated error type (correlationKey) on one facet. */
export const FACET_ERROR_SCHEMA = "spire-stress-facet-error@1";

export function readJsonFile(path: string): unknown {
    const text = readFileSync(path, "utf8");
    /* eslint-disable @typescript-eslint/no-unsafe-assignment */
    const parsed = JSON.parse(text);
    /* eslint-enable @typescript-eslint/no-unsafe-assignment */
    return parsed as unknown;
}

/**
 * Expect models to start facet triage with `TITLE: …` (one line), then body markdown.
 * Strips that line from `markdown` so the UI does not show it twice.
 */
export function splitLlmTriageTitleMarkdown(raw: string): {
    title?: string;
    markdown: string;
} {
    const trimmed = raw.trim();
    const nl = trimmed.indexOf("\n");
    const firstLine = nl === -1 ? trimmed : trimmed.slice(0, nl).trim();
    const rest = nl === -1 ? "" : trimmed.slice(nl + 1);
    const m = /^\s*TITLE:\s*(.+?)\s*$/i.exec(firstLine);
    if (m?.[1] === undefined) {
        return { markdown: trimmed };
    }
    let title = m[1].trim();
    if (title.length > 120) {
        title = `${title.slice(0, 117)}…`;
    }
    const markdown = rest.replace(/^\s*\n+/, "").trim();
    return {
        title: title.length > 0 ? title : undefined,
        markdown: markdown.length > 0 ? markdown : "_No detail body._",
    };
}

export function extractChoiceContent(data: unknown): string | undefined {
    /* eslint-disable @typescript-eslint/no-unsafe-assignment */
    if (typeof data !== "object" || data === null) {
        return undefined;
    }
    const choices = Reflect.get(data, "choices");
    if (!Array.isArray(choices) || choices.length === 0) {
        return undefined;
    }
    const ch0: unknown = choices[0];
    if (typeof ch0 !== "object" || ch0 === null) {
        return undefined;
    }
    const message = Reflect.get(ch0, "message");
    if (typeof message !== "object" || message === null) {
        return undefined;
    }
    const content = Reflect.get(message, "content");
    /* eslint-enable @typescript-eslint/no-unsafe-assignment */
    return typeof content === "string" ? content : undefined;
}

export function loadManifestFromEnv(): unknown {
    const manPath = process.env["STRESS_MANIFEST_PATH"]?.trim();
    if (manPath === undefined || manPath.length === 0 || !existsSync(manPath)) {
        return null;
    }
    const m = readJsonFile(manPath);
    if (typeof m !== "object" || m === null) {
        return m;
    }
    /* eslint-disable @typescript-eslint/no-unsafe-assignment */
    const files = Reflect.get(m, "files");
    /* eslint-enable @typescript-eslint/no-unsafe-assignment */
    if (Array.isArray(files)) {
        return {
            ...m,
            files: files.slice(0, 400),
            filesTruncated: files.length > 400,
        };
    }
    return m;
}

export function loadDocsPackFromEnv(): unknown {
    const docsPath = process.env["STRESS_DOCS_PACK_PATH"]?.trim();
    if (
        docsPath === undefined ||
        docsPath.length === 0 ||
        !existsSync(docsPath)
    ) {
        return null;
    }
    const d = readJsonFile(docsPath);
    if (typeof d !== "object" || d === null) {
        return d;
    }
    /* eslint-disable @typescript-eslint/no-unsafe-assignment */
    const files = Reflect.get(d, "files");
    /* eslint-enable @typescript-eslint/no-unsafe-assignment */
    if (Array.isArray(files)) {
        /* eslint-disable @typescript-eslint/no-unsafe-assignment */
        return {
            fileCount: Reflect.get(d, "fileCount"),
            files: files.slice(0, 24),
            filesTruncated: files.length > 24,
            generatedAt: Reflect.get(d, "generatedAt"),
            root: Reflect.get(d, "root"),
            schema: Reflect.get(d, "schema"),
        };
        /* eslint-enable @typescript-eslint/no-unsafe-assignment */
    }
    return d;
}

export function triageSystemPrompt(): string {
    return [
        "You assist with triaging a stress-test incident for a TypeScript server (Spire) and client (libvex).",
        "Rules:",
        "- Use ONLY facts present in the user JSON (bundle.run, bundle.telemetry, bundle.correlation, bundle.fatal if present, manifest, docsPack).",
        "- If bundle.schema is `" +
            LIVE_TRIAGE_SCHEMA +
            "`, there is no fatal incident: use bundle.telemetry (live snapshot), bundle.correlation, and bundle.run only.",
        "- If bundle.schema is `" +
            FACET_ERROR_SCHEMA +
            "`, analyze a single deduplicated error type: use bundle.focus, bundle.samples (recent occurrences), and bundle.run. manifest/docsPack are optional global context only.",
        "- Samples use `clientSurfaceKey` (same naming as the libvex stress catalog), `protocolPath`, `primaryClientPath` (first `Client.*` method), `surfaceTitle`, `requestInputs` (sanitized), optional `extra`, `runPhase` / `runPhaseLabel`, and HTTP fields when present. Treat these as observed context, not proof of server behavior.",
        "- Do not invent internal runner opcode names; refer to `clientSurfaceKey`, `protocolPath`, and `surfaceTitle` only.",
        "- Do NOT assert root causes or stack frames beyond what is shown. Prefer hypotheses labeled as suggestions.",
        "- If evidence is insufficient, say so and list what additional data would help.",
        "Output format: first line MUST be exactly `TITLE: <short plain-language incident name, max ~80 chars>` (no markdown, no quotes). Second line blank. Then markdown sections: Summary (facts only), Likely areas to inspect (suggestions), Repro / context fields from bundle, Correlated failure groups when present, Open questions.",
    ].join("\n");
}

/** Short system prompt when the user JSON is already minimal (live facet triage). */
export function triageFacetMinimalSystemPrompt(): string {
    return [
        "You triage one deduplicated stress **issue** (one correlationKey). JSON has: `focus` (protocolPath, primaryClientPath, surfaceTitle, correlationKey), `run` (scenario, spireHost, load shape), `samples` (1–2 rows).",
        "Each sample may include: `harnessCall` (synthetic JS: Client API + sanitized args), `req` (sanitized requestInputs), `http` (method/status/url/body snippet when Axios), `stk` (trimmed Node `Error.stack` from the harness / libvex client), `message`.",
        "Use only those fields. `protocolPath` / `primaryClientPath` name the published API surface—align your wording with them.",
        "Do not invent stack frames, file paths, or root causes beyond the text given. Label guesses as suggestions.",
        "First line MUST be exactly `TITLE: <short plain-language name, max ~72 chars>` (like a human-written GitHub issue title). Second line blank. Then markdown: Summary (facts), Suggested checks (suggestions), Open questions.",
    ].join(" ");
}

function isRecord(v: unknown): v is Record<string, unknown> {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}

function truncateStr(s: string, max: number): string {
    if (s.length <= max) {
        return s;
    }
    return `${s.slice(0, Math.max(0, max - 1))}…`;
}

function truncateJsonValue(v: unknown, maxChars: number): unknown {
    if (v === undefined) {
        return undefined;
    }
    try {
        const t = JSON.stringify(v);
        if (t.length <= maxChars) {
            return JSON.parse(t) as unknown;
        }
        return { _truncated: truncateStr(t, maxChars) };
    } catch {
        return undefined;
    }
}

function compactAxiosForLlm(ax: unknown): Record<string, unknown> | undefined {
    if (!isRecord(ax)) {
        return undefined;
    }
    const url = ax["url"];
    const dataSnippet = ax["dataSnippet"];
    return {
        method: ax["method"] ?? null,
        status: ax["status"] ?? null,
        statusText: ax["statusText"] ?? null,
        url: typeof url === "string" ? truncateStr(url, 140) : null,
        ...(typeof dataSnippet === "string" && dataSnippet.length > 0
            ? { dataSnippet: truncateStr(dataSnippet, 220) }
            : {}),
    };
}

function stackHead(
    stack: unknown,
    maxLines: number,
    maxChars = 3800,
): string | undefined {
    if (typeof stack !== "string" || stack.length === 0) {
        return undefined;
    }
    const lines = stack.split("\n").map((l) => l.trim());
    const head = lines.slice(0, maxLines).join("\n");
    return head.length > 0 ? truncateStr(head, maxChars) : undefined;
}

/** One sample row for the model: enough to see HTTP + which Client call + where it blew up. */
function sampleMessageString(v: unknown): string {
    if (typeof v === "string") {
        return v;
    }
    if (v instanceof Error) {
        return v.message;
    }
    if (v !== null && v !== undefined) {
        try {
            return JSON.stringify(v);
        } catch {
            return "[message]";
        }
    }
    return "";
}

function shrinkFacetSampleRow(s: unknown): Record<string, unknown> {
    if (!isRecord(s)) {
        return {};
    }
    const hc = s["harnessCall"];
    return {
        http: compactAxiosForLlm(s["axios"]),
        harnessCall: typeof hc === "string" ? truncateStr(hc, 1400) : undefined,
        message: truncateStr(sampleMessageString(s["message"]), 360),
        primaryClientPath: s["primaryClientPath"],
        protocolPath: s["protocolPath"],
        req: truncateJsonValue(s["requestInputs"], 900),
        stk: stackHead(s["stack"], 24, 4200),
    };
}

function shrinkFacetRun(run: unknown): Record<string, unknown> {
    if (!isRecord(run)) {
        return {};
    }
    return {
        burstIndex: run["burstIndex"] ?? run["currentBurst"],
        clientCount: run["clientCount"],
        concurrency: run["concurrency"],
        runPhaseLabel: run["runPhaseLabel"] ?? run["phase"],
        scenario: run["scenario"],
        spireHost: run["spireHost"] ?? run["host"],
    };
}

/**
 * Strip facet triage JSON down for small-context local models (LM Studio, etc.).
 * Caller may still set {@link SPIRE_STRESS_LLM_FULL}=1 to skip this in {@link runLlmTriage}.
 */
export function shrinkFacetErrorBundleForLlm(bundle: unknown): unknown {
    if (!isRecord(bundle)) {
        return bundle;
    }
    const schema = bundle["schema"];
    if (schema !== FACET_ERROR_SCHEMA) {
        return bundle;
    }
    const rawSamples = bundle["samples"];
    const samples = Array.isArray(rawSamples) ? rawSamples : [];
    const cap = Math.min(3, samples.length);
    const samplesSmall = samples
        .slice(0, cap)
        .map((s) => shrinkFacetSampleRow(s));
    return {
        focus: bundle["focus"],
        generatedAt: bundle["generatedAt"],
        run: shrinkFacetRun(bundle["run"]),
        samples: samplesSmall,
        schema: FACET_ERROR_SCHEMA,
    };
}

function isFacetErrorBundle(bundle: unknown): boolean {
    return isRecord(bundle) && bundle["schema"] === FACET_ERROR_SCHEMA;
}

export function buildLiveTriageBundle(
    snapshot: unknown,
    run: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
    let failureGroups: unknown = [];
    if (typeof snapshot === "object" && snapshot !== null) {
        /* eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- Reflect.get typed as any */
        const fg = Reflect.get(snapshot, "failureGroups");
        if (Array.isArray(fg)) {
            failureGroups = fg;
        }
    }
    return {
        correlation: { failureGroups },
        generatedAt: new Date().toISOString(),
        run: {
            ...run,
            note: "Live dashboard triage (not a post-fatal issue bundle).",
        },
        schema: LIVE_TRIAGE_SCHEMA,
        telemetry: snapshot,
    };
}

export function buildFacetErrorTriageBundle(input: {
    readonly focus: {
        readonly clientSurfaceKey: string;
        readonly correlationKey: string;
        readonly primaryClientPath: string;
        readonly protocolPath: string;
        readonly sampleMessage: string;
        readonly surfaceTitle?: string;
    };
    readonly run: Readonly<Record<string, unknown>>;
    readonly samples: readonly unknown[];
}): Record<string, unknown> {
    return {
        focus: {
            clientSurfaceKey: input.focus.clientSurfaceKey,
            correlationKey: input.focus.correlationKey,
            primaryClientPath: input.focus.primaryClientPath,
            protocolPath: input.focus.protocolPath,
            sampleMessage: input.focus.sampleMessage,
            surfaceTitle: input.focus.surfaceTitle,
        },
        generatedAt: new Date().toISOString(),
        run: input.run,
        samples: input.samples,
        schema: FACET_ERROR_SCHEMA,
    };
}

export function loadIssueBundleFromEnv(): unknown {
    const bundlePath =
        process.env["STRESS_ISSUE_BUNDLE_PATH"]?.trim() ??
        STRESS_ISSUE_BUNDLE_PATH;
    if (!existsSync(bundlePath)) {
        throw new Error(
            `Issue bundle not found: ${bundlePath} (run until a fatal writes it, or set STRESS_ISSUE_BUNDLE_PATH)`,
        );
    }
    const bundle = readJsonFile(bundlePath);
    if (typeof bundle !== "object" || bundle === null) {
        throw new Error(`Invalid bundle JSON (expected object): ${bundlePath}`);
    }
    return bundle;
}

export type LlmTriageOk = {
    readonly detail?: string;
    readonly endpoint: string;
    readonly markdown: string;
    readonly model: string;
    readonly ok: true;
    /** Parsed from leading `TITLE:` line when the model follows instructions. */
    readonly title?: string;
};

export type LlmTriageErr = {
    readonly detail?: string;
    readonly httpStatus?: number;
    readonly message: string;
    readonly ok: false;
};

export type LlmTriageResult = LlmTriageOk | LlmTriageErr;

/**
 * Map `…/v1/chat/completions` → `…/v1/models` for OpenAI-compatible servers (LM Studio, etc.).
 */
function openAiModelsListUrlFromChatCompletionsUrl(
    chatCompletionsUrl: string,
): string | undefined {
    try {
        const u = new URL(chatCompletionsUrl);
        const path = u.pathname.replace(/\/$/, "");
        if (path.endsWith("/chat/completions")) {
            u.pathname = `${path.slice(0, -"/chat/completions".length)}/models`;
            return u.toString();
        }
        if (path.endsWith("/v1")) {
            u.pathname = `${path}/models`;
            return u.toString();
        }
        return undefined;
    } catch {
        return undefined;
    }
}

/** First model id from `GET /v1/models` (`data[].id`), when the user has a single server model loaded. */
async function pickFirstListedModelId(
    chatCompletionsUrl: string,
    getHeaders: Record<string, string>,
): Promise<string | undefined> {
    const modelsUrl =
        openAiModelsListUrlFromChatCompletionsUrl(chatCompletionsUrl);
    if (modelsUrl === undefined) {
        return undefined;
    }
    try {
        const res = await axios.get(modelsUrl, {
            headers: getHeaders,
            timeout: 8_000,
            validateStatus: () => true,
        });
        if (res.status < 200 || res.status >= 300) {
            return undefined;
        }
        const body: unknown = res.data;
        if (typeof body !== "object" || body === null) {
            return undefined;
        }
        /* eslint-disable @typescript-eslint/no-unsafe-assignment */
        const data = Reflect.get(body, "data");
        /* eslint-enable @typescript-eslint/no-unsafe-assignment */
        if (!Array.isArray(data) || data.length === 0) {
            return undefined;
        }
        const first: unknown = data[0];
        if (typeof first !== "object" || first === null) {
            return undefined;
        }
        /* eslint-disable @typescript-eslint/no-unsafe-assignment */
        const id = Reflect.get(first, "id");
        /* eslint-enable @typescript-eslint/no-unsafe-assignment */
        return typeof id === "string" && id.length > 0 ? id : undefined;
    } catch {
        return undefined;
    }
}

/**
 * Cheap auto-naming: one `TITLE:` line, tiny payload (no full triage markdown).
 */
export async function runLlmIssueTitleOnly(input: {
    readonly focus: {
        readonly correlationKey: string;
        readonly primaryClientPath: string;
        readonly protocolPath: string;
        readonly sampleMessage: string;
        readonly surfaceTitle?: string;
    };
    readonly http?: Readonly<Record<string, unknown>>;
}): Promise<LlmTriageResult> {
    const url =
        process.env["SPIRE_STRESS_LLM_URL"]?.trim() ||
        STRESS_LLM_TRIAGE_DEFAULT_URL;
    const apiKey = process.env["SPIRE_STRESS_LLM_API_KEY"]?.trim();

    const getHeaders: Record<string, string> = {};
    if (apiKey !== undefined && apiKey.length > 0) {
        getHeaders["Authorization"] = `Bearer ${apiKey}`;
    }

    const envModel = process.env["SPIRE_STRESS_LLM_MODEL"]?.trim();
    let model =
        envModel !== undefined && envModel.length > 0
            ? envModel
            : await pickFirstListedModelId(url, getHeaders);
    if (model === undefined || model.length === 0) {
        model = "local-model";
    }

    const userPayload = JSON.stringify(input, null, 0).slice(0, 8000);
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...getHeaders,
    };

    const system =
        "You name stress-run incidents for engineers. Reply with exactly one line, no code fences: TITLE: <short plain-language name, max 72 characters>. Use only facts from the JSON. No other text.";

    const res = await axios.post(
        url,
        {
            messages: [
                { content: system, role: "system" },
                { content: `Issue JSON:\n${userPayload}`, role: "user" },
            ],
            max_tokens: 96,
            model,
            temperature: 0.1,
        },
        { headers, timeout: 25_000, validateStatus: () => true },
    );

    if (res.status < 200 || res.status >= 300) {
        let detail: string | undefined;
        try {
            detail = JSON.stringify(res.data).slice(0, 4000);
        } catch {
            detail = undefined;
        }
        return {
            detail,
            httpStatus: res.status,
            message: `LLM HTTP ${String(res.status)}`,
            ok: false,
        };
    }

    const text = extractChoiceContent(res.data);
    if (typeof text === "string" && text.length > 0) {
        const firstLine = text.trim().split("\n")[0]?.trim() ?? text.trim();
        const m = /TITLE:\s*(.+)/i.exec(firstLine);
        const titleRaw = m?.[1]?.trim();
        const title =
            titleRaw !== undefined && titleRaw.length > 0
                ? titleRaw.length > 120
                    ? `${titleRaw.slice(0, 117)}…`
                    : titleRaw
                : undefined;
        return {
            endpoint: url,
            markdown: "",
            model,
            ok: true,
            ...(title !== undefined ? { title } : {}),
        };
    }
    return {
        message: "LLM returned empty content",
        ok: false,
    };
}

export async function runLlmTriage(input: {
    readonly bundle: unknown;
    readonly docsPack: unknown;
    readonly manifest: unknown;
}): Promise<LlmTriageResult> {
    const url =
        process.env["SPIRE_STRESS_LLM_URL"]?.trim() ||
        STRESS_LLM_TRIAGE_DEFAULT_URL;
    const apiKey = process.env["SPIRE_STRESS_LLM_API_KEY"]?.trim();

    const getHeaders: Record<string, string> = {};
    if (apiKey !== undefined && apiKey.length > 0) {
        getHeaders["Authorization"] = `Bearer ${apiKey}`;
    }

    const envModel = process.env["SPIRE_STRESS_LLM_MODEL"]?.trim();
    let model =
        envModel !== undefined && envModel.length > 0
            ? envModel
            : await pickFirstListedModelId(url, getHeaders);
    if (model === undefined || model.length === 0) {
        model = "local-model";
    }

    const fullContext =
        process.env["SPIRE_STRESS_LLM_FULL"]?.trim() === "1" ||
        process.env["SPIRE_STRESS_LLM_FULL_CONTEXT"]?.trim() === "1";
    const useFacetMinimal = isFacetErrorBundle(input.bundle) && !fullContext;

    let bundleOut: unknown = input.bundle;
    let docsOut: unknown = input.docsPack;
    let manifestOut: unknown = input.manifest;
    if (useFacetMinimal) {
        bundleOut = shrinkFacetErrorBundleForLlm(input.bundle);
        docsOut = null;
        manifestOut = null;
    }

    const maxUserChars = useFacetMinimal ? 14_000 : 120_000;
    const userPayload = JSON.stringify(
        { bundle: bundleOut, docsPack: docsOut, manifest: manifestOut },
        null,
        useFacetMinimal ? 0 : 2,
    ).slice(0, maxUserChars);

    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...getHeaders,
    };

    const systemPrompt = useFacetMinimal
        ? triageFacetMinimalSystemPrompt()
        : triageSystemPrompt();

    const res = await axios.post(
        url,
        {
            messages: [
                { content: systemPrompt, role: "system" },
                {
                    content: useFacetMinimal
                        ? `Triage JSON:\n${userPayload}`
                        : `Incident JSON (truncated if huge):\n${userPayload}`,
                    role: "user",
                },
            ],
            model,
            temperature: 0.2,
        },
        { headers, timeout: 120_000, validateStatus: () => true },
    );

    if (res.status < 200 || res.status >= 300) {
        let detail: string | undefined;
        try {
            detail = JSON.stringify(res.data).slice(0, 4000);
        } catch {
            detail = undefined;
        }
        return {
            detail,
            httpStatus: res.status,
            message: `LLM HTTP ${String(res.status)}`,
            ok: false,
        };
    }

    const text = extractChoiceContent(res.data);
    if (typeof text === "string" && text.length > 0) {
        const { title, markdown } = splitLlmTriageTitleMarkdown(text);
        return {
            endpoint: url,
            markdown,
            model,
            ok: true,
            ...(title !== undefined ? { title } : {}),
        };
    }
    let fallback: string;
    try {
        fallback = JSON.stringify(res.data, null, 2);
    } catch {
        fallback = "[unserializable LLM response]";
    }
    const split = splitLlmTriageTitleMarkdown(fallback);
    return {
        detail: fallback.slice(0, 12_000),
        endpoint: url,
        markdown: split.markdown,
        model,
        ok: true,
        ...(split.title !== undefined ? { title: split.title } : {}),
    };
}
