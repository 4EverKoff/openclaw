import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  requestEgressApprovalPassword,
  resolvePendingEgressApprovalRequest,
  shouldRequireEgressApproval,
  verifyEgressApprovalPassword,
} from "./egress-approval-password.js";

const tempDirs: string[] = [];

function createPasswordPayload(password: string) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
  });
  return {
    algorithm: "scrypt",
    params: { N: 16384, r: 8, p: 1, keyLength: 64 },
    salt: salt.toString("base64"),
    hash: hash.toString("base64"),
  };
}

function writePasswordFile(password: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-egress-approval-"));
  tempDirs.push(dir);
  const file = path.join(dir, "password.json");
  fs.writeFileSync(file, JSON.stringify(createPasswordPayload(password)));
  return file;
}

function writePendingRequest(requestsDir: string, id: string, createdAt: string): string {
  const file = path.join(requestsDir, `${id}.json`);
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        id,
        status: "pending",
        createdAt,
        expiresAt: "2030-01-01T00:00:00.000Z",
        toolName: "message",
        categories: "external_send",
        sessionKey: "main",
        paramsSummary: "- target: outside",
      },
      null,
      2,
    ),
  );
  return file;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("egress approval password", () => {
  it("requires approval for external sends and dangerous actions only", () => {
    expect(shouldRequireEgressApproval("message")).toBe(true);
    expect(shouldRequireEgressApproval("exec")).toBe(true);
    expect(shouldRequireEgressApproval("read")).toBe(false);
    expect(shouldRequireEgressApproval("update_plan")).toBe(false);
  });

  it("verifies scrypt password hashes", () => {
    const payload = createPasswordPayload("correct horse battery");

    expect(verifyEgressApprovalPassword("correct horse battery", payload)).toBe(true);
    expect(verifyEgressApprovalPassword("wrong password", payload)).toBe(false);
  });

  it("blocks approval-required tools when a password file is explicit and no local TTY is available", async () => {
    const passwordFile = writePasswordFile("correct horse battery");

    const result = await requestEgressApprovalPassword({
      toolName: "message",
      params: { action: "send", target: "outside" },
      sessionKey: "main",
      passwordFile,
    });

    expect(result.approved).toBe(false);
    if (!result.approved) {
      expect(result.reason).toContain("Egress approval password required");
    }
  });

  it("allows approval-required tools after a pending file request is approved", async () => {
    const passwordFile = writePasswordFile("correct horse battery");
    const requestsDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-egress-requests-"));
    tempDirs.push(requestsDir);
    const previous = process.env.OPENCLAW_EGRESS_APPROVAL_PENDING_TEST_ENABLE;
    process.env.OPENCLAW_EGRESS_APPROVAL_PENDING_TEST_ENABLE = "1";
    try {
      const pending = requestEgressApprovalPassword({
        toolName: "message",
        params: { action: "send", target: "outside" },
        sessionKey: "main",
        passwordFile,
        requestsDir,
        timeoutMs: 2500,
      });

      let requestFile = "";
      const startedAt = Date.now();
      while (!requestFile && Date.now() - startedAt < 1000) {
        const files = fs.readdirSync(requestsDir).filter((file) => file.endsWith(".json"));
        requestFile = files[0] ? path.join(requestsDir, files[0]) : "";
        if (!requestFile) {
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
      }
      expect(requestFile).not.toBe("");
      const request = JSON.parse(fs.readFileSync(requestFile, "utf8"));
      fs.writeFileSync(requestFile, JSON.stringify({ ...request, status: "approved" }));

      await expect(pending).resolves.toEqual({ approved: true });
    } finally {
      if (previous === undefined) {
        delete process.env.OPENCLAW_EGRESS_APPROVAL_PENDING_TEST_ENABLE;
      } else {
        process.env.OPENCLAW_EGRESS_APPROVAL_PENDING_TEST_ENABLE = previous;
      }
    }
  });

  it("approves the newest pending request after password verification", async () => {
    const passwordFile = writePasswordFile("correct horse battery");
    const requestsDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-egress-requests-"));
    tempDirs.push(requestsDir);
    writePendingRequest(requestsDir, "older", "2026-01-01T00:00:00.000Z");
    const newestFile = writePendingRequest(requestsDir, "newer", "2026-01-02T00:00:00.000Z");

    const result = await resolvePendingEgressApprovalRequest({
      decision: "approve",
      passwordFile,
      requestsDir,
      readPassword: async (prompt) => {
        expect(prompt).toContain("Egress approval password");
        return "correct horse battery";
      },
      now: new Date("2026-01-02T01:00:00.000Z"),
    });

    expect(result).toMatchObject({
      ok: true,
      requestFile: newestFile,
      decision: "approved",
    });
    const request = JSON.parse(fs.readFileSync(newestFile, "utf8"));
    expect(request).toMatchObject({
      status: "approved",
      resolvedBy: "local-cli",
      approvedAt: "2026-01-02T01:00:00.000Z",
    });
  });

  it("rejects pending approval when the password is wrong", async () => {
    const passwordFile = writePasswordFile("correct horse battery");
    const requestsDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-egress-requests-"));
    tempDirs.push(requestsDir);
    const requestFile = writePendingRequest(requestsDir, "request", "2026-01-01T00:00:00.000Z");

    const result = await resolvePendingEgressApprovalRequest({
      decision: "approve",
      requestFile,
      passwordFile,
      readPassword: async () => "wrong password",
      now: new Date("2026-01-01T01:00:00.000Z"),
    });

    expect(result).toMatchObject({
      ok: false,
      reason: "Egress approval password verification failed.",
    });
    const request = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    expect(request.status).toBe("pending");
  });

  it("denies a pending request without password verification", async () => {
    const requestsDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-egress-requests-"));
    tempDirs.push(requestsDir);
    const requestFile = writePendingRequest(requestsDir, "request", "2026-01-01T00:00:00.000Z");

    const result = await resolvePendingEgressApprovalRequest({
      decision: "deny",
      requestFile,
      readPassword: async () => {
        throw new Error("should not ask");
      },
      now: new Date("2026-01-01T01:00:00.000Z"),
    });

    expect(result).toMatchObject({
      ok: true,
      requestFile,
      decision: "denied",
    });
    const request = JSON.parse(fs.readFileSync(requestFile, "utf8"));
    expect(request).toMatchObject({
      status: "denied",
      resolvedBy: "local-cli",
      deniedAt: "2026-01-01T01:00:00.000Z",
    });
  });

  it("allows non-sensitive tools even with a password file", async () => {
    const passwordFile = writePasswordFile("correct horse battery");

    await expect(
      requestEgressApprovalPassword({
        toolName: "read",
        params: { path: "README.md" },
        sessionKey: "main",
        passwordFile,
      }),
    ).resolves.toEqual({ approved: true });
  });
});
