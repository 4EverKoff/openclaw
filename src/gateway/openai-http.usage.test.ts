import { describe, expect, it } from "vitest";
import { __testOnlyOpenAiHttp } from "./openai-http.js";

const { resolveChatCompletionUsage, buildOpenAiResponseMetadata } = __testOnlyOpenAiHttp;

describe("resolveChatCompletionUsage", () => {
  it("maps agentMeta.usage to OpenAI prompt/completion/total fields", () => {
    const result = {
      meta: {
        agentMeta: {
          usage: { input: 120, output: 42, cacheRead: 10, total: 172 },
        },
      },
    };

    expect(resolveChatCompletionUsage(result)).toEqual({
      prompt_tokens: 130,
      completion_tokens: 42,
      total_tokens: 172,
    });
  });

  it("falls back to agentMeta.lastCallUsage when agentMeta.usage is missing", () => {
    const result = {
      meta: {
        agentMeta: {
          lastCallUsage: { input: 80, output: 20, total: 100 },
        },
      },
    };

    expect(resolveChatCompletionUsage(result)).toEqual({
      prompt_tokens: 80,
      completion_tokens: 20,
      total_tokens: 100,
    });
  });

  it("falls back to agentMeta.lastCallUsage when agentMeta.usage is all zero", () => {
    const result = {
      meta: {
        agentMeta: {
          usage: { input: 0, output: 0, total: 0 },
          lastCallUsage: { input: 55, output: 7, total: 62 },
        },
      },
    };

    expect(resolveChatCompletionUsage(result)).toEqual({
      prompt_tokens: 55,
      completion_tokens: 7,
      total_tokens: 62,
    });
  });

  it("returns zeros when both agentMeta.usage and lastCallUsage are absent", () => {
    const result = { meta: { agentMeta: {} } };

    expect(resolveChatCompletionUsage(result)).toEqual({
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    });
  });

  it("returns zeros when the result has no meta at all", () => {
    expect(resolveChatCompletionUsage({})).toEqual({
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    });
    expect(resolveChatCompletionUsage(null)).toEqual({
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    });
  });
});

describe("buildOpenAiResponseMetadata", () => {
  it("emits the OCM-compatible redacted context metrics shape", () => {
    const metadata = buildOpenAiResponseMetadata({
      meta: {
        agentMeta: { contextTokens: 272_000 },
        contextMetrics: {
          sessionMessageCount: 8,
          sessionPriorUserMessageCount: 3,
          sessionPriorUserMessageChars: 1234,
          sessionPriorAssistantMessageCount: 2,
          sessionPriorAssistantMessageChars: 567,
        },
        systemPromptReport: {
          sessionId: "SECRET_SESSION_ID_SHOULD_NOT_LEAK",
          sessionKey: "SECRET_SESSION_SHOULD_NOT_LEAK",
          workspaceDir: "/Users/koff/OpenClawShare/workspace/agents/investigator",
          injectedWorkspaceFiles: [
            {
              name: "AGENTS.md",
              path: "/Users/koff/SECRET_PATH_SHOULD_NOT_LEAK/AGENTS.md",
              rawChars: 100,
              injectedChars: 80,
              truncated: false,
            },
            {
              name: "MEMORY.md",
              path: "/Users/koff/SECRET_PATH_SHOULD_NOT_LEAK/MEMORY.md",
              rawChars: 50,
              injectedChars: 25,
              truncated: true,
            },
          ],
          tools: {
            schemaChars: 321,
            entries: [{ name: "secret-tool", schema: "Authorization: Bearer nope" }],
          },
          skills: {
            promptChars: 654,
            entries: [{ name: "secret-skill", prompt: "nope" }],
          },
        },
      },
    });

    expect(metadata).toMatchObject({
      contextMetrics: {
        contextTokens: 272_000,
        systemPromptReportPresent: true,
        bootstrapInjectedChars: 105,
        bootstrapRawChars: 150,
        bootstrapFileCount: 2,
        bootstrapTruncatedFileCount: 1,
        toolsSchemaChars: 321,
        toolsCount: 1,
        skillsPromptChars: 654,
        skillsCount: 1,
        sessionMessageCount: 8,
        sessionPriorUserMessageCount: 3,
        sessionPriorUserMessageChars: 1234,
        sessionPriorAssistantMessageCount: 2,
        sessionPriorAssistantMessageChars: 567,
      },
      systemPromptReport: {
        bootstrap: {
          injectedChars: 105,
          rawChars: 150,
          fileCount: 2,
          truncatedFileCount: 1,
        },
        tools: { schemaChars: 321, count: 1 },
        skills: { promptChars: 654, count: 1 },
      },
      contextTokens: 272_000,
      sessionMessageCount: 8,
    });

    const serialized = JSON.stringify(metadata);
    expect(serialized).not.toContain("SECRET_SESSION_ID_SHOULD_NOT_LEAK");
    expect(serialized).not.toContain("SECRET_SESSION_SHOULD_NOT_LEAK");
    expect(serialized).not.toContain("SECRET_PATH_SHOULD_NOT_LEAK");
    expect(serialized).not.toContain("Authorization: Bearer nope");
    expect(serialized).not.toContain("secret-skill");
  });

  it("omits metadata when no gateway context signals are available", () => {
    expect(buildOpenAiResponseMetadata({ meta: { agentMeta: {} } })).toBeUndefined();
    expect(buildOpenAiResponseMetadata({})).toBeUndefined();
  });
});
