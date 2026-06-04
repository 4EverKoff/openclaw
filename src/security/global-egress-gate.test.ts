import { describe, expect, it } from "vitest";
import {
  classifyGlobalEgressGateTool,
  decideGlobalEgressGate,
  resolveGlobalEgressGateOrigin,
} from "./global-egress-gate.js";

describe("global egress gate", () => {
  it("treats hook sessions as untrusted external origins", () => {
    expect(resolveGlobalEgressGateOrigin({ sessionKey: "hook:gmail:inbox" })).toBe("external_hook");
    expect(resolveGlobalEgressGateOrigin({ sessionKey: "hook:webhook:deploy" })).toBe(
      "external_hook",
    );
    expect(resolveGlobalEgressGateOrigin({ sessionKey: "main" })).toBe("trusted");
  });

  it("classifies sensitive tool categories", () => {
    expect(classifyGlobalEgressGateTool("message")).toEqual(["external_send"]);
    expect(classifyGlobalEgressGateTool("read")).toEqual(["sensitive_read"]);
    expect(classifyGlobalEgressGateTool("exec")).toEqual(["dangerous_action"]);
    expect(classifyGlobalEgressGateTool("apply-patch")).toEqual(["dangerous_action"]);
  });

  it("blocks sensitive tools from external hook sessions", () => {
    const decision = decideGlobalEgressGate({
      toolName: "message",
      sessionKey: "hook:gmail:attacker",
    });

    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.origin).toBe("external_hook");
      expect(decision.categories).toEqual(["external_send"]);
      expect(decision.reason).toContain("Direct operator intent is required");
    }
  });

  it("allows non-sensitive tools from external hook sessions", () => {
    expect(
      decideGlobalEgressGate({
        toolName: "update_plan",
        sessionKey: "hook:webhook:triage",
      }),
    ).toEqual({ allowed: true });
  });

  it("allows sensitive tools from trusted sessions for existing approval policy to handle", () => {
    expect(
      decideGlobalEgressGate({
        toolName: "exec",
        sessionKey: "main",
      }),
    ).toEqual({ allowed: true });
  });

  it("treats plugins outside an explicit allowlist as untrusted", () => {
    expect(
      resolveGlobalEgressGateOrigin({
        sessionKey: "main",
        toolOwner: { pluginId: "unknown-plugin" },
        trustedPluginIds: ["trusted-plugin"],
      }),
    ).toBe("untrusted_plugin");
    expect(
      resolveGlobalEgressGateOrigin({
        sessionKey: "main",
        toolOwner: { pluginId: "trusted-plugin" },
        trustedPluginIds: ["trusted-plugin"],
      }),
    ).toBe("trusted");
  });

  it("blocks unknown tools from untrusted plugins and bundle MCP", () => {
    const pluginDecision = decideGlobalEgressGate({
      toolName: "custom_upload_everything",
      toolOwner: { pluginId: "unknown-plugin" },
      trustedPluginIds: ["trusted-plugin"],
    });
    const mcpDecision = decideGlobalEgressGate({
      toolName: "filesystem__read_secret",
      toolOwner: { pluginId: "bundle-mcp" },
      trustedPluginIds: ["trusted-plugin"],
    });

    expect(pluginDecision.allowed).toBe(false);
    expect(mcpDecision.allowed).toBe(false);
    if (!pluginDecision.allowed) {
      expect(pluginDecision.origin).toBe("untrusted_plugin");
      expect(pluginDecision.categories).toEqual(["dangerous_action"]);
    }
    if (!mcpDecision.allowed) {
      expect(mcpDecision.origin).toBe("untrusted_mcp");
      expect(mcpDecision.categories).toEqual(["dangerous_action"]);
    }
  });
});
