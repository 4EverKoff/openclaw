import { isExternalHookSession } from "./external-content-source.js";

export type GlobalEgressGateActionCategory =
  | "external_send"
  | "sensitive_read"
  | "dangerous_action";

export type GlobalEgressGateOrigin =
  | "trusted"
  | "external_hook"
  | "untrusted_skill"
  | "untrusted_plugin"
  | "untrusted_mcp"
  | "unknown";

export type GlobalEgressGateDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly reason: string;
      readonly categories: readonly GlobalEgressGateActionCategory[];
      readonly origin: GlobalEgressGateOrigin;
    };

export type GlobalEgressGateToolOwner = {
  readonly pluginId?: string;
};

const EXTERNAL_SEND_TOOLS = new Set([
  "message",
  "tts",
  "image_generate",
  "video_generate",
  "music_generate",
  "cron",
]);

const SENSITIVE_READ_TOOLS = new Set([
  "read",
  "pdf",
  "image",
  "sessions_history",
  "memory_get",
  "memory_search",
  "file_fetch",
  "dir_fetch",
]);

const DANGEROUS_ACTION_TOOLS = new Set([
  "exec",
  "bash",
  "write",
  "edit",
  "apply_patch",
  "process",
  "gateway",
  "nodes",
  "canvas",
  "subagents",
  "sessions_send",
  "sessions_spawn",
]);

function normalizeToolName(toolName: string): string {
  return toolName.trim().toLowerCase().replace(/-/g, "_");
}

export function classifyGlobalEgressGateTool(
  toolName: string,
): readonly GlobalEgressGateActionCategory[] {
  const normalized = normalizeToolName(toolName);
  const categories: GlobalEgressGateActionCategory[] = [];
  if (EXTERNAL_SEND_TOOLS.has(normalized)) {
    categories.push("external_send");
  }
  if (SENSITIVE_READ_TOOLS.has(normalized)) {
    categories.push("sensitive_read");
  }
  if (DANGEROUS_ACTION_TOOLS.has(normalized)) {
    categories.push("dangerous_action");
  }
  return categories;
}

export function resolveGlobalEgressGateOrigin(params: {
  readonly sessionKey?: string;
  readonly toolOwner?: GlobalEgressGateToolOwner;
  readonly trustedPluginIds?: readonly string[];
}): GlobalEgressGateOrigin {
  if (params.sessionKey && isExternalHookSession(params.sessionKey)) {
    return "external_hook";
  }
  const pluginId = params.toolOwner?.pluginId?.trim();
  if (pluginId) {
    const trusted =
      params.trustedPluginIds === undefined
        ? true
        : params.trustedPluginIds.some((candidate) => candidate.trim() === pluginId);
    if (!trusted) {
      return pluginId === "bundle-mcp" ? "untrusted_mcp" : "untrusted_plugin";
    }
  }
  return "trusted";
}

export function decideGlobalEgressGate(params: {
  readonly toolName: string;
  readonly sessionKey?: string;
  readonly origin?: GlobalEgressGateOrigin;
  readonly toolOwner?: GlobalEgressGateToolOwner;
  readonly trustedPluginIds?: readonly string[];
}): GlobalEgressGateDecision {
  const origin =
    params.origin ??
    resolveGlobalEgressGateOrigin({
      sessionKey: params.sessionKey,
      toolOwner: params.toolOwner,
      trustedPluginIds: params.trustedPluginIds,
    });
  if (origin === "trusted") {
    return { allowed: true };
  }

  const categories = [...classifyGlobalEgressGateTool(params.toolName)];
  if (
    categories.length === 0 &&
    (origin === "untrusted_skill" || origin === "untrusted_plugin" || origin === "untrusted_mcp")
  ) {
    categories.push("dangerous_action");
  }
  if (categories.length === 0) {
    return { allowed: true };
  }

  return {
    allowed: false,
    origin,
    categories,
    reason:
      `Action refused by global egress gate. Origin ${origin} cannot invoke ` +
      `${categories.join(", ")} tool "${params.toolName}". Direct operator intent is required.`,
  };
}
