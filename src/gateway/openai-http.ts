import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { ImageContent } from "../agents/command/types.js";
import {
  hasNonzeroUsage,
  normalizeUsage,
  toOpenAiChatCompletionsUsage,
  type NormalizedUsage,
} from "../agents/usage.js";
import { createDefaultDeps } from "../cli/deps.js";
import { agentCommandFromIngress } from "../commands/agent.js";
import type { GatewayHttpChatCompletionsConfig } from "../config/types.gateway.js";
import { emitAgentEvent, onAgentEvent } from "../infra/agent-events.js";
import { logWarn } from "../logger.js";
import { estimateBase64DecodedBytes } from "../media/base64.js";
import {
  DEFAULT_INPUT_IMAGE_MAX_BYTES,
  DEFAULT_INPUT_IMAGE_MIMES,
  DEFAULT_INPUT_MAX_REDIRECTS,
  DEFAULT_INPUT_TIMEOUT_MS,
  extractImageContentFromSource,
  normalizeMimeList,
  type InputImageLimits,
  type InputImageSource,
} from "../media/input-files.js";
import { defaultRuntime } from "../runtime.js";
import {
  normalizeLowercaseStringOrEmpty,
  normalizeOptionalString,
} from "../shared/string-coerce.js";
import { resolveAssistantStreamDeltaText } from "./agent-event-assistant-text.js";
import {
  buildAgentMessageFromConversationEntries,
  type ConversationEntry,
} from "./agent-prompt.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { sendJson, setSseHeaders, watchClientDisconnect, writeDone } from "./http-common.js";
import { handleGatewayPostJsonEndpoint } from "./http-endpoint-helpers.js";
import {
  resolveGatewayRequestContext,
  resolveOpenAiCompatModelOverride,
  resolveOpenAiCompatibleHttpOperatorScopes,
  resolveOpenAiCompatibleHttpSenderIsOwner,
} from "./http-utils.js";
import { normalizeInputHostnameAllowlist } from "./input-allowlist.js";

type OpenAiHttpOptions = {
  auth: ResolvedGatewayAuth;
  config?: GatewayHttpChatCompletionsConfig;
  maxBodyBytes?: number;
  trustedProxies?: string[];
  allowRealIpFallback?: boolean;
  rateLimiter?: AuthRateLimiter;
};

type OpenAiChatMessage = {
  role?: unknown;
  content?: unknown;
  name?: unknown;
};

type OpenAiChatCompletionRequest = {
  model?: unknown;
  stream?: unknown;
  // Naming/style reference: src/agents/openai-transport-stream.ts:1262-1273
  stream_options?: unknown;
  messages?: unknown;
  user?: unknown;
};

const DEFAULT_OPENAI_CHAT_COMPLETIONS_BODY_BYTES = 20 * 1024 * 1024;
const IMAGE_ONLY_USER_MESSAGE = "User sent image(s) with no text.";
const DEFAULT_OPENAI_MAX_IMAGE_PARTS = 8;
const DEFAULT_OPENAI_MAX_TOTAL_IMAGE_BYTES = 20 * 1024 * 1024;
const DEFAULT_OPENAI_IMAGE_LIMITS: InputImageLimits = {
  allowUrl: false,
  allowedMimes: new Set(DEFAULT_INPUT_IMAGE_MIMES),
  maxBytes: DEFAULT_INPUT_IMAGE_MAX_BYTES,
  maxRedirects: DEFAULT_INPUT_MAX_REDIRECTS,
  timeoutMs: DEFAULT_INPUT_TIMEOUT_MS,
};

type ResolvedOpenAiChatCompletionsLimits = {
  maxBodyBytes: number;
  maxImageParts: number;
  maxTotalImageBytes: number;
  images: InputImageLimits;
};

function resolveOpenAiChatCompletionsLimits(
  config: GatewayHttpChatCompletionsConfig | undefined,
): ResolvedOpenAiChatCompletionsLimits {
  const imageConfig = config?.images;
  return {
    maxBodyBytes: config?.maxBodyBytes ?? DEFAULT_OPENAI_CHAT_COMPLETIONS_BODY_BYTES,
    maxImageParts:
      typeof config?.maxImageParts === "number"
        ? Math.max(0, Math.floor(config.maxImageParts))
        : DEFAULT_OPENAI_MAX_IMAGE_PARTS,
    maxTotalImageBytes:
      typeof config?.maxTotalImageBytes === "number"
        ? Math.max(1, Math.floor(config.maxTotalImageBytes))
        : DEFAULT_OPENAI_MAX_TOTAL_IMAGE_BYTES,
    images: {
      allowUrl: imageConfig?.allowUrl ?? DEFAULT_OPENAI_IMAGE_LIMITS.allowUrl,
      urlAllowlist: normalizeInputHostnameAllowlist(imageConfig?.urlAllowlist),
      allowedMimes: normalizeMimeList(imageConfig?.allowedMimes, DEFAULT_INPUT_IMAGE_MIMES),
      maxBytes: imageConfig?.maxBytes ?? DEFAULT_INPUT_IMAGE_MAX_BYTES,
      maxRedirects: imageConfig?.maxRedirects ?? DEFAULT_INPUT_MAX_REDIRECTS,
      timeoutMs: imageConfig?.timeoutMs ?? DEFAULT_INPUT_TIMEOUT_MS,
    },
  };
}

function writeSse(res: ServerResponse, data: unknown) {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function buildAgentCommandInput(params: {
  prompt: { message: string; extraSystemPrompt?: string; images?: ImageContent[] };
  modelOverride?: string;
  sessionKey: string;
  runId: string;
  messageChannel: string;
  senderIsOwner: boolean;
  abortSignal?: AbortSignal;
}) {
  return {
    message: params.prompt.message,
    extraSystemPrompt: params.prompt.extraSystemPrompt,
    images: params.prompt.images,
    model: params.modelOverride,
    sessionKey: params.sessionKey,
    runId: params.runId,
    deliver: false as const,
    messageChannel: params.messageChannel,
    bestEffortDeliver: false as const,
    senderIsOwner: params.senderIsOwner,
    allowModelOverride: true as const,
    abortSignal: params.abortSignal,
  };
}

function writeAssistantRoleChunk(res: ServerResponse, params: { runId: string; model: string }) {
  writeSse(res, {
    id: params.runId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: params.model,
    choices: [{ index: 0, delta: { role: "assistant" } }],
  });
}

function writeAssistantContentChunk(
  res: ServerResponse,
  params: { runId: string; model: string; content: string; finishReason: "stop" | null },
) {
  writeSse(res, {
    id: params.runId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: params.model,
    choices: [
      {
        index: 0,
        delta: { content: params.content },
        finish_reason: params.finishReason,
      },
    ],
  });
}

function writeAssistantStopChunk(res: ServerResponse, params: { runId: string; model: string }) {
  writeSse(res, {
    id: params.runId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: params.model,
    choices: [
      {
        index: 0,
        delta: {},
        finish_reason: "stop",
      },
    ],
  });
}

function writeUsageChunk(
  res: ServerResponse,
  params: {
    runId: string;
    model: string;
    usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
    metadata?: OpenAiResponseMetadata;
  },
) {
  writeSse(res, {
    id: params.runId,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model: params.model,
    choices: [],
    usage: params.usage,
    ...(params.metadata ? { metadata: params.metadata } : {}),
  });
}

function asMessages(val: unknown): OpenAiChatMessage[] {
  return Array.isArray(val) ? (val as OpenAiChatMessage[]) : [];
}

function extractTextContent(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (!part || typeof part !== "object") {
          return "";
        }
        const type = (part as { type?: unknown }).type;
        const text = (part as { text?: unknown }).text;
        const inputText = (part as { input_text?: unknown }).input_text;
        if (type === "text" && typeof text === "string") {
          return text;
        }
        if (type === "input_text" && typeof text === "string") {
          return text;
        }
        if (typeof inputText === "string") {
          return inputText;
        }
        return "";
      })
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

function resolveImageUrlPart(part: unknown): string | undefined {
  if (!part || typeof part !== "object") {
    return undefined;
  }
  const imageUrl = (part as { image_url?: unknown }).image_url;
  if (typeof imageUrl === "string") {
    const trimmed = imageUrl.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (!imageUrl || typeof imageUrl !== "object") {
    return undefined;
  }
  const rawUrl = (imageUrl as { url?: unknown }).url;
  if (typeof rawUrl !== "string") {
    return undefined;
  }
  const trimmed = rawUrl.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function extractImageUrls(content: unknown): string[] {
  if (!Array.isArray(content)) {
    return [];
  }
  const urls: string[] = [];
  for (const part of content) {
    if (!part || typeof part !== "object") {
      continue;
    }
    if ((part as { type?: unknown }).type !== "image_url") {
      continue;
    }
    const url = resolveImageUrlPart(part);
    if (url) {
      urls.push(url);
    }
  }
  return urls;
}

type ActiveTurnContext = {
  activeTurnIndex: number;
  activeUserMessageIndex: number;
  urls: string[];
};

function parseImageUrlToSource(url: string): InputImageSource {
  const dataUriMatch = /^data:([^,]*?),(.*)$/is.exec(url);
  if (dataUriMatch) {
    const metadata = normalizeOptionalString(dataUriMatch[1]) ?? "";
    const data = dataUriMatch[2] ?? "";
    const metadataParts = metadata
      .split(";")
      .map((part) => normalizeOptionalString(part) ?? "")
      .filter(Boolean);
    const isBase64 = metadataParts.some(
      (part) => normalizeLowercaseStringOrEmpty(part) === "base64",
    );
    if (!isBase64) {
      throw new Error("image_url data URI must be base64 encoded");
    }
    if (!(normalizeOptionalString(data) ?? "")) {
      throw new Error("image_url data URI is missing payload data");
    }
    const mediaTypeRaw = metadataParts.find((part) => part.includes("/"));
    return {
      type: "base64",
      mediaType: mediaTypeRaw,
      data,
    };
  }
  return { type: "url", url };
}

function resolveActiveTurnContext(messagesUnknown: unknown): ActiveTurnContext {
  const messages = asMessages(messagesUnknown);
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const msg = messages[i];
    if (!msg || typeof msg !== "object") {
      continue;
    }
    const role = normalizeOptionalString(msg.role) ?? "";
    const normalizedRole = role === "function" ? "tool" : role;
    if (normalizedRole !== "user" && normalizedRole !== "tool") {
      continue;
    }
    return {
      activeTurnIndex: i,
      activeUserMessageIndex: normalizedRole === "user" ? i : -1,
      urls: normalizedRole === "user" ? extractImageUrls(msg.content) : [],
    };
  }
  return { activeTurnIndex: -1, activeUserMessageIndex: -1, urls: [] };
}

async function resolveImagesForRequest(
  activeTurnContext: Pick<ActiveTurnContext, "urls">,
  limits: ResolvedOpenAiChatCompletionsLimits,
): Promise<ImageContent[]> {
  const urls = activeTurnContext.urls;
  if (urls.length === 0) {
    return [];
  }
  if (urls.length > limits.maxImageParts) {
    throw new Error(`Too many image_url parts (${urls.length}; limit ${limits.maxImageParts})`);
  }

  const images: ImageContent[] = [];
  let totalBytes = 0;
  for (const url of urls) {
    const source = parseImageUrlToSource(url);
    if (source.type === "base64") {
      const sourceBytes = estimateBase64DecodedBytes(source.data);
      if (totalBytes + sourceBytes > limits.maxTotalImageBytes) {
        throw new Error(
          `Total image payload too large (${totalBytes + sourceBytes}; limit ${limits.maxTotalImageBytes})`,
        );
      }
    }

    const image = await extractImageContentFromSource(source, limits.images);
    totalBytes += estimateBase64DecodedBytes(image.data);
    if (totalBytes > limits.maxTotalImageBytes) {
      throw new Error(
        `Total image payload too large (${totalBytes}; limit ${limits.maxTotalImageBytes})`,
      );
    }
    images.push(image);
  }
  return images;
}

type RedactedSystemPromptReport = {
  bootstrap?: {
    injectedChars?: number;
    rawChars?: number;
    fileCount?: number;
    truncatedFileCount?: number;
  };
  tools?: {
    schemaChars?: number;
    count?: number;
  };
  skills?: {
    promptChars?: number;
    count?: number;
  };
};

type OpenAiContextMetrics = {
  contextTokens?: number;
  systemPromptReportPresent: boolean;
  bootstrapInjectedChars?: number;
  bootstrapRawChars?: number;
  bootstrapFileCount?: number;
  bootstrapTruncatedFileCount?: number;
  toolsSchemaChars?: number;
  toolsCount?: number;
  skillsPromptChars?: number;
  skillsCount?: number;
  sessionFileBytes?: number;
  sessionMessageCount?: number;
  sessionPriorUserMessageCount?: number;
  sessionPriorUserMessageChars?: number;
  sessionPriorAssistantMessageCount?: number;
  sessionPriorAssistantMessageChars?: number;
};

type OpenAiResponseMetadata = {
  contextMetrics: OpenAiContextMetrics;
  systemPromptReport?: RedactedSystemPromptReport;
  contextTokens?: number;
  sessionFileBytes?: number;
  sessionMessageCount?: number;
  sessionPriorUserMessageCount?: number;
  sessionPriorUserMessageChars?: number;
  sessionPriorAssistantMessageCount?: number;
  sessionPriorAssistantMessageChars?: number;
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asArray(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function readNonNegativeInteger(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return undefined;
  }
  return Math.floor(value);
}

function firstIntegerFromRecord(
  record: Record<string, unknown> | undefined,
  keys: string[],
): number | undefined {
  if (!record) {
    return undefined;
  }
  for (const key of keys) {
    const value = readNonNegativeInteger(record[key]);
    if (value !== undefined) {
      return value;
    }
  }
  return undefined;
}

function countArray(value: unknown): number | undefined {
  return Array.isArray(value) ? value.length : undefined;
}

function sumArrayIntegerField(items: unknown[] | undefined, keys: string[]): number | undefined {
  if (!items) {
    return undefined;
  }
  let total = 0;
  let found = false;
  for (const item of items) {
    const record = asRecord(item);
    const value = firstIntegerFromRecord(record, keys);
    if (value === undefined) {
      continue;
    }
    total += value;
    found = true;
  }
  return found ? total : undefined;
}

function countTruthyArrayField(items: unknown[] | undefined, key: string): number | undefined {
  if (!items) {
    return undefined;
  }
  return items.filter((item) => Boolean(asRecord(item)?.[key])).length;
}

function hasKeys(value: object): boolean {
  return Object.keys(value).length > 0;
}

function buildRedactedSystemPromptReport(report: unknown): RedactedSystemPromptReport | undefined {
  const reportRecord = asRecord(report);
  if (!reportRecord) {
    return undefined;
  }

  const injectedWorkspaceFiles = asArray(reportRecord.injectedWorkspaceFiles);
  const bootstrapRecord = asRecord(reportRecord.bootstrap);
  const toolsRecord = asRecord(reportRecord.tools);
  const skillsRecord = asRecord(reportRecord.skills);

  const bootstrap: NonNullable<RedactedSystemPromptReport["bootstrap"]> = {};
  const bootstrapInjectedChars =
    firstIntegerFromRecord(bootstrapRecord, ["injectedChars", "injected_chars"]) ??
    sumArrayIntegerField(injectedWorkspaceFiles, ["injectedChars", "injected_chars"]);
  const bootstrapRawChars =
    firstIntegerFromRecord(bootstrapRecord, ["rawChars", "raw_chars"]) ??
    sumArrayIntegerField(injectedWorkspaceFiles, ["rawChars", "raw_chars"]);
  const bootstrapFileCount =
    firstIntegerFromRecord(bootstrapRecord, ["fileCount", "file_count"]) ??
    countArray(injectedWorkspaceFiles);
  const bootstrapTruncatedFileCount =
    firstIntegerFromRecord(bootstrapRecord, ["truncatedFileCount", "truncated_file_count"]) ??
    countTruthyArrayField(injectedWorkspaceFiles, "truncated");
  if (bootstrapInjectedChars !== undefined) {
    bootstrap.injectedChars = bootstrapInjectedChars;
  }
  if (bootstrapRawChars !== undefined) {
    bootstrap.rawChars = bootstrapRawChars;
  }
  if (bootstrapFileCount !== undefined) {
    bootstrap.fileCount = bootstrapFileCount;
  }
  if (bootstrapTruncatedFileCount !== undefined) {
    bootstrap.truncatedFileCount = bootstrapTruncatedFileCount;
  }

  const tools: NonNullable<RedactedSystemPromptReport["tools"]> = {};
  const toolsSchemaChars = firstIntegerFromRecord(toolsRecord, ["schemaChars", "schema_chars"]);
  const toolsCount =
    firstIntegerFromRecord(toolsRecord, ["count"]) ?? countArray(toolsRecord?.entries);
  if (toolsSchemaChars !== undefined) {
    tools.schemaChars = toolsSchemaChars;
  }
  if (toolsCount !== undefined) {
    tools.count = toolsCount;
  }

  const skills: NonNullable<RedactedSystemPromptReport["skills"]> = {};
  const skillsPromptChars = firstIntegerFromRecord(skillsRecord, ["promptChars", "prompt_chars"]);
  const skillsCount =
    firstIntegerFromRecord(skillsRecord, ["count"]) ?? countArray(skillsRecord?.entries);
  if (skillsPromptChars !== undefined) {
    skills.promptChars = skillsPromptChars;
  }
  if (skillsCount !== undefined) {
    skills.count = skillsCount;
  }

  const redacted: RedactedSystemPromptReport = {};
  if (hasKeys(bootstrap)) {
    redacted.bootstrap = bootstrap;
  }
  if (hasKeys(tools)) {
    redacted.tools = tools;
  }
  if (hasKeys(skills)) {
    redacted.skills = skills;
  }
  return redacted;
}

function buildOpenAiResponseMetadata(result: unknown): OpenAiResponseMetadata | undefined {
  const meta = asRecord((result as { meta?: unknown } | null)?.meta);
  const agentMeta = asRecord(meta?.agentMeta);
  const reportRecord = asRecord(meta?.systemPromptReport);
  const runtimeMetrics =
    asRecord(meta?.contextMetrics) ?? asRecord(meta?.context_metrics) ?? undefined;
  const contextTokens = firstIntegerFromRecord(agentMeta, ["contextTokens", "context_tokens"]);
  const redactedReport = buildRedactedSystemPromptReport(reportRecord);

  const sessionFileBytes = firstIntegerFromRecord(runtimeMetrics, [
    "sessionFileBytes",
    "session_file_bytes",
  ]);
  const sessionMessageCount = firstIntegerFromRecord(runtimeMetrics, [
    "sessionMessageCount",
    "session_message_count",
  ]);
  const sessionPriorUserMessageCount = firstIntegerFromRecord(runtimeMetrics, [
    "sessionPriorUserMessageCount",
    "session_prior_user_message_count",
  ]);
  const sessionPriorUserMessageChars = firstIntegerFromRecord(runtimeMetrics, [
    "sessionPriorUserMessageChars",
    "session_prior_user_message_chars",
  ]);
  const sessionPriorAssistantMessageCount = firstIntegerFromRecord(runtimeMetrics, [
    "sessionPriorAssistantMessageCount",
    "session_prior_assistant_message_count",
  ]);
  const sessionPriorAssistantMessageChars = firstIntegerFromRecord(runtimeMetrics, [
    "sessionPriorAssistantMessageChars",
    "session_prior_assistant_message_chars",
  ]);

  const hasAnySignal =
    Boolean(reportRecord) ||
    contextTokens !== undefined ||
    sessionFileBytes !== undefined ||
    sessionMessageCount !== undefined ||
    sessionPriorUserMessageCount !== undefined ||
    sessionPriorUserMessageChars !== undefined ||
    sessionPriorAssistantMessageCount !== undefined ||
    sessionPriorAssistantMessageChars !== undefined;
  if (!hasAnySignal) {
    return undefined;
  }

  const contextMetrics: OpenAiContextMetrics = {
    systemPromptReportPresent: Boolean(reportRecord),
  };
  if (contextTokens !== undefined) {
    contextMetrics.contextTokens = contextTokens;
  }
  if (redactedReport?.bootstrap?.injectedChars !== undefined) {
    contextMetrics.bootstrapInjectedChars = redactedReport.bootstrap.injectedChars;
  }
  if (redactedReport?.bootstrap?.rawChars !== undefined) {
    contextMetrics.bootstrapRawChars = redactedReport.bootstrap.rawChars;
  }
  if (redactedReport?.bootstrap?.fileCount !== undefined) {
    contextMetrics.bootstrapFileCount = redactedReport.bootstrap.fileCount;
  }
  if (redactedReport?.bootstrap?.truncatedFileCount !== undefined) {
    contextMetrics.bootstrapTruncatedFileCount = redactedReport.bootstrap.truncatedFileCount;
  }
  if (redactedReport?.tools?.schemaChars !== undefined) {
    contextMetrics.toolsSchemaChars = redactedReport.tools.schemaChars;
  }
  if (redactedReport?.tools?.count !== undefined) {
    contextMetrics.toolsCount = redactedReport.tools.count;
  }
  if (redactedReport?.skills?.promptChars !== undefined) {
    contextMetrics.skillsPromptChars = redactedReport.skills.promptChars;
  }
  if (redactedReport?.skills?.count !== undefined) {
    contextMetrics.skillsCount = redactedReport.skills.count;
  }
  if (sessionFileBytes !== undefined) {
    contextMetrics.sessionFileBytes = sessionFileBytes;
  }
  if (sessionMessageCount !== undefined) {
    contextMetrics.sessionMessageCount = sessionMessageCount;
  }
  if (sessionPriorUserMessageCount !== undefined) {
    contextMetrics.sessionPriorUserMessageCount = sessionPriorUserMessageCount;
  }
  if (sessionPriorUserMessageChars !== undefined) {
    contextMetrics.sessionPriorUserMessageChars = sessionPriorUserMessageChars;
  }
  if (sessionPriorAssistantMessageCount !== undefined) {
    contextMetrics.sessionPriorAssistantMessageCount = sessionPriorAssistantMessageCount;
  }
  if (sessionPriorAssistantMessageChars !== undefined) {
    contextMetrics.sessionPriorAssistantMessageChars = sessionPriorAssistantMessageChars;
  }

  const metadata: OpenAiResponseMetadata = { contextMetrics };
  if (redactedReport && hasKeys(redactedReport)) {
    metadata.systemPromptReport = redactedReport;
  }
  if (contextTokens !== undefined) {
    metadata.contextTokens = contextTokens;
  }
  if (sessionFileBytes !== undefined) {
    metadata.sessionFileBytes = sessionFileBytes;
  }
  if (sessionMessageCount !== undefined) {
    metadata.sessionMessageCount = sessionMessageCount;
  }
  if (sessionPriorUserMessageCount !== undefined) {
    metadata.sessionPriorUserMessageCount = sessionPriorUserMessageCount;
  }
  if (sessionPriorUserMessageChars !== undefined) {
    metadata.sessionPriorUserMessageChars = sessionPriorUserMessageChars;
  }
  if (sessionPriorAssistantMessageCount !== undefined) {
    metadata.sessionPriorAssistantMessageCount = sessionPriorAssistantMessageCount;
  }
  if (sessionPriorAssistantMessageChars !== undefined) {
    metadata.sessionPriorAssistantMessageChars = sessionPriorAssistantMessageChars;
  }
  return metadata;
}

export const __testOnlyOpenAiHttp = {
  resolveImagesForRequest,
  resolveOpenAiChatCompletionsLimits,
  resolveChatCompletionUsage,
  buildOpenAiResponseMetadata,
};

function buildAgentPrompt(
  messagesUnknown: unknown,
  activeUserMessageIndex: number,
): {
  message: string;
  extraSystemPrompt?: string;
} {
  const messages = asMessages(messagesUnknown);

  const systemParts: string[] = [];
  const conversationEntries: ConversationEntry[] = [];

  for (const [i, msg] of messages.entries()) {
    if (!msg || typeof msg !== "object") {
      continue;
    }
    const role = normalizeOptionalString(msg.role) ?? "";
    const content = extractTextContent(msg.content).trim();
    const hasImage = extractImageUrls(msg.content).length > 0;
    if (!role) {
      continue;
    }
    if (role === "system" || role === "developer") {
      if (content) {
        systemParts.push(content);
      }
      continue;
    }

    const normalizedRole = role === "function" ? "tool" : role;
    if (normalizedRole !== "user" && normalizedRole !== "assistant" && normalizedRole !== "tool") {
      continue;
    }

    // Keep the image-only placeholder scoped to the active user turn so we don't
    // mention historical image-only turns whose bytes are intentionally not replayed.
    const messageContent =
      normalizedRole === "user" && !content && hasImage && i === activeUserMessageIndex
        ? IMAGE_ONLY_USER_MESSAGE
        : content;
    if (!messageContent) {
      continue;
    }

    const name = normalizeOptionalString(msg.name) ?? "";
    const sender =
      normalizedRole === "assistant"
        ? "Assistant"
        : normalizedRole === "user"
          ? "User"
          : name
            ? `Tool:${name}`
            : "Tool";

    conversationEntries.push({
      role: normalizedRole,
      entry: { sender, body: messageContent },
    });
  }

  const message = buildAgentMessageFromConversationEntries(conversationEntries);

  return {
    message,
    extraSystemPrompt: systemParts.length > 0 ? systemParts.join("\n\n") : undefined,
  };
}

function coerceRequest(val: unknown): OpenAiChatCompletionRequest {
  if (!val || typeof val !== "object") {
    return {};
  }
  return val as OpenAiChatCompletionRequest;
}

function resolveAgentResponseText(result: unknown): string {
  const payloads = (result as { payloads?: Array<{ text?: string }> } | null)?.payloads;
  if (!Array.isArray(payloads) || payloads.length === 0) {
    return "No response from OpenClaw.";
  }
  const content = payloads
    .map((p) => (typeof p.text === "string" ? p.text : ""))
    .filter(Boolean)
    .join("\n\n");
  return content || "No response from OpenClaw.";
}

type AgentUsageMeta = {
  input?: number;
  output?: number;
  cacheRead?: number;
  cacheWrite?: number;
  total?: number;
};

function resolveAgentRunUsage(result: unknown): NormalizedUsage | undefined {
  const agentMeta = (
    result as {
      meta?: {
        agentMeta?: {
          usage?: AgentUsageMeta;
          lastCallUsage?: AgentUsageMeta;
        };
      };
    } | null
  )?.meta?.agentMeta;
  const primary = normalizeUsage(agentMeta?.usage);
  if (hasNonzeroUsage(primary)) {
    return primary;
  }
  const fallback = normalizeUsage(agentMeta?.lastCallUsage);
  if (hasNonzeroUsage(fallback)) {
    return fallback;
  }
  return primary ?? fallback;
}

function resolveChatCompletionUsage(result: unknown): {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
} {
  return toOpenAiChatCompletionsUsage(resolveAgentRunUsage(result));
}

function resolveIncludeUsageForStreaming(payload: OpenAiChatCompletionRequest): boolean {
  // Keep parsing aligned with OpenAI wire-format field names.
  // Flow reference: src/agents/openai-transport-stream.ts:1262-1273
  const streamOptions = payload.stream_options;
  if (!streamOptions || typeof streamOptions !== "object" || Array.isArray(streamOptions)) {
    return false;
  }
  return (streamOptions as { include_usage?: unknown }).include_usage === true;
}

export async function handleOpenAiHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: OpenAiHttpOptions,
): Promise<boolean> {
  const limits = resolveOpenAiChatCompletionsLimits(opts.config);
  const handled = await handleGatewayPostJsonEndpoint(req, res, {
    pathname: "/v1/chat/completions",
    requiredOperatorMethod: "chat.send",
    // Compat HTTP uses a different scope model from generic HTTP helpers:
    // shared-secret bearer auth is treated as full operator access here.
    resolveOperatorScopes: resolveOpenAiCompatibleHttpOperatorScopes,
    auth: opts.auth,
    trustedProxies: opts.trustedProxies,
    allowRealIpFallback: opts.allowRealIpFallback,
    rateLimiter: opts.rateLimiter,
    maxBodyBytes: opts.maxBodyBytes ?? limits.maxBodyBytes,
  });
  if (handled === false) {
    return false;
  }
  if (!handled) {
    return true;
  }
  // On the compat surface, shared-secret bearer auth is also treated as an
  // owner sender so owner-only tool policy matches the documented contract.
  const senderIsOwner = resolveOpenAiCompatibleHttpSenderIsOwner(req, handled.requestAuth);

  const payload = coerceRequest(handled.body);
  const stream = Boolean(payload.stream);
  const streamIncludeUsage = stream && resolveIncludeUsageForStreaming(payload);
  const model = typeof payload.model === "string" ? payload.model : "openclaw";
  const user = typeof payload.user === "string" ? payload.user : undefined;

  const { agentId, sessionKey, messageChannel } = resolveGatewayRequestContext({
    req,
    model,
    user,
    sessionPrefix: "openai",
    defaultMessageChannel: "webchat",
    useMessageChannelHeader: true,
  });
  const { modelOverride, errorMessage: modelError } = await resolveOpenAiCompatModelOverride({
    req,
    agentId,
    model,
  });
  if (modelError) {
    sendJson(res, 400, {
      error: { message: modelError, type: "invalid_request_error" },
    });
    return true;
  }
  const activeTurnContext = resolveActiveTurnContext(payload.messages);
  const prompt = buildAgentPrompt(payload.messages, activeTurnContext.activeUserMessageIndex);
  let images: ImageContent[] = [];
  try {
    images = await resolveImagesForRequest(activeTurnContext, limits);
  } catch (err) {
    logWarn(`openai-compat: invalid image_url content: ${String(err)}`);
    sendJson(res, 400, {
      error: {
        message: "Invalid image_url content in `messages`.",
        type: "invalid_request_error",
      },
    });
    return true;
  }

  if (!prompt.message && images.length === 0) {
    sendJson(res, 400, {
      error: {
        message: "Missing user message in `messages`.",
        type: "invalid_request_error",
      },
    });
    return true;
  }

  const runId = `chatcmpl_${randomUUID()}`;
  const deps = createDefaultDeps();
  const abortController = new AbortController();
  const commandInput = buildAgentCommandInput({
    prompt: {
      message: prompt.message,
      extraSystemPrompt: prompt.extraSystemPrompt,
      images: images.length > 0 ? images : undefined,
    },
    modelOverride,
    sessionKey,
    runId,
    messageChannel,
    abortSignal: abortController.signal,
    senderIsOwner,
  });

  if (!stream) {
    const stopWatchingDisconnect = watchClientDisconnect(req, res, abortController);
    try {
      const result = await agentCommandFromIngress(commandInput, defaultRuntime, deps);

      if (abortController.signal.aborted) {
        return true;
      }

      const content = resolveAgentResponseText(result);
      const usage = resolveChatCompletionUsage(result);
      const metadata = buildOpenAiResponseMetadata(result);

      sendJson(res, 200, {
        id: runId,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model,
        choices: [
          {
            index: 0,
            message: { role: "assistant", content },
            finish_reason: "stop",
          },
        ],
        usage,
        ...(metadata ? { metadata } : {}),
      });
    } catch (err) {
      if (abortController.signal.aborted) {
        return true;
      }
      logWarn(`openai-compat: chat completion failed: ${String(err)}`);
      sendJson(res, 500, {
        error: { message: "internal error", type: "api_error" },
      });
    } finally {
      stopWatchingDisconnect();
    }
    return true;
  }

  setSseHeaders(res);

  let wroteRole = false;
  let wroteStopChunk = false;
  let sawAssistantDelta = false;
  let finalUsage:
    | {
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
      }
    | undefined;
  let finalMetadata: OpenAiResponseMetadata | undefined;
  let finalizeRequested = false;
  let closed = false;
  let stopWatchingDisconnect = () => {};

  const maybeFinalize = () => {
    if (closed || !finalizeRequested) {
      return;
    }
    if (streamIncludeUsage && !finalUsage) {
      return;
    }
    closed = true;
    stopWatchingDisconnect();
    unsubscribe();
    if (!wroteStopChunk) {
      writeAssistantStopChunk(res, { runId, model });
      wroteStopChunk = true;
    }
    if (streamIncludeUsage && finalUsage) {
      writeUsageChunk(res, {
        runId,
        model,
        usage: finalUsage,
        ...(finalMetadata ? { metadata: finalMetadata } : {}),
      });
    }
    writeDone(res);
    res.end();
  };

  const requestFinalize = () => {
    finalizeRequested = true;
    maybeFinalize();
  };

  const unsubscribe = onAgentEvent((evt) => {
    if (evt.runId !== runId) {
      return;
    }
    if (closed) {
      return;
    }

    if (evt.stream === "assistant") {
      const content = resolveAssistantStreamDeltaText(evt) ?? "";
      if (!content) {
        return;
      }

      if (!wroteRole) {
        wroteRole = true;
        writeAssistantRoleChunk(res, { runId, model });
      }

      sawAssistantDelta = true;
      writeAssistantContentChunk(res, {
        runId,
        model,
        content,
        finishReason: null,
      });
      return;
    }

    if (evt.stream === "lifecycle") {
      const phase = evt.data?.phase;
      if (phase === "end" || phase === "error") {
        requestFinalize();
      }
    }
  });

  stopWatchingDisconnect = watchClientDisconnect(req, res, abortController, () => {
    closed = true;
    unsubscribe();
  });

  void (async () => {
    try {
      const result = await agentCommandFromIngress(commandInput, defaultRuntime, deps);

      if (closed) {
        return;
      }

      finalUsage = resolveChatCompletionUsage(result);
      finalMetadata = buildOpenAiResponseMetadata(result);

      if (!sawAssistantDelta) {
        if (!wroteRole) {
          wroteRole = true;
          writeAssistantRoleChunk(res, { runId, model });
        }

        const content = resolveAgentResponseText(result);

        sawAssistantDelta = true;
        writeAssistantContentChunk(res, {
          runId,
          model,
          content,
          finishReason: null,
        });
      }
      requestFinalize();
    } catch (err) {
      if (closed || abortController.signal.aborted) {
        return;
      }
      logWarn(`openai-compat: streaming chat completion failed: ${String(err)}`);
      writeAssistantContentChunk(res, {
        runId,
        model,
        content: "Error: internal error",
        finishReason: "stop",
      });
      wroteStopChunk = true;
      finalUsage = {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
      };
      emitAgentEvent({
        runId,
        stream: "lifecycle",
        data: { phase: "error" },
      });
      requestFinalize();
    } finally {
      if (!closed) {
        emitAgentEvent({
          runId,
          stream: "lifecycle",
          data: { phase: "end" },
        });
      }
    }
  })();

  return true;
}
