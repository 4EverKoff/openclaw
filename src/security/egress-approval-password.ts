import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { classifyGlobalEgressGateTool } from "./global-egress-gate.js";

type PasswordHashPayload = {
  algorithm?: string;
  params?: {
    N?: number;
    r?: number;
    p?: number;
    keyLength?: number;
  };
  salt?: string;
  hash?: string;
};

type PendingEgressApprovalPayload = {
  id?: string;
  status?: string;
  createdAt?: string;
  expiresAt?: string;
  toolName?: string;
  categories?: string;
  sessionKey?: string;
  toolCallId?: string;
  paramsSummary?: string;
  approvedAt?: string;
  deniedAt?: string;
  resolvedBy?: string;
};

export type EgressApprovalRequest = {
  toolName: string;
  sessionKey?: string;
  toolCallId?: string;
  params?: unknown;
  passwordFile?: string;
  requestsDir?: string;
  timeoutMs?: number;
};

export type EgressApprovalResult =
  | { approved: true }
  | {
      approved: false;
      reason: string;
    };

export type ResolvePendingEgressApprovalOptions = {
  requestFile?: string;
  requestsDir?: string;
  passwordFile?: string;
  decision: "approve" | "deny";
  readPassword?: (prompt: string) => Promise<string>;
  now?: Date;
};

export type ResolvePendingEgressApprovalResult =
  | {
      ok: true;
      requestFile: string;
      request: PendingEgressApprovalPayload;
      decision: "approved" | "denied";
    }
  | {
      ok: false;
      reason: string;
      requestFile?: string;
      request?: PendingEgressApprovalPayload;
    };

const DEFAULT_PASSWORD_FILE = path.join(
  os.homedir(),
  ".openclaw",
  "security",
  "egress-approval-password.json",
);
const DEFAULT_REQUESTS_DIR = path.join(
  os.homedir(),
  ".openclaw",
  "security",
  "egress-approval-requests",
);
const DEFAULT_PENDING_TIMEOUT_MS = 120_000;

function isVitest(): boolean {
  return process.env.VITEST === "true" || Boolean(process.env.VITEST);
}

export function resolveEgressApprovalPasswordFile(override?: string): string {
  return (
    override?.trim() || process.env.OPENCLAW_EGRESS_APPROVAL_PASSWORD_FILE || DEFAULT_PASSWORD_FILE
  );
}

export function resolveEgressApprovalRequestsDir(override?: string): string {
  return (
    override?.trim() || process.env.OPENCLAW_EGRESS_APPROVAL_REQUESTS_DIR || DEFAULT_REQUESTS_DIR
  );
}

export function shouldRequireEgressApproval(toolName: string): boolean {
  const categories = classifyGlobalEgressGateTool(toolName);
  return categories.includes("external_send") || categories.includes("dangerous_action");
}

export function isEgressApprovalConfigured(passwordFile?: string): boolean {
  const resolved = resolveEgressApprovalPasswordFile(passwordFile);
  if (isVitest() && !passwordFile && process.env.OPENCLAW_EGRESS_APPROVAL_TEST_ENABLE !== "1") {
    return false;
  }
  try {
    return fs.statSync(resolved).isFile();
  } catch {
    return false;
  }
}

export function verifyEgressApprovalPassword(
  password: string,
  payload: PasswordHashPayload,
): boolean {
  if (payload.algorithm !== "scrypt") {
    return false;
  }
  const expected = Buffer.from(payload.hash ?? "", "base64");
  const salt = Buffer.from(payload.salt ?? "", "base64");
  if (expected.length === 0 || salt.length === 0) {
    return false;
  }
  const actual = crypto.scryptSync(password, salt, expected.length, {
    N: payload.params?.N ?? 16384,
    r: payload.params?.r ?? 8,
    p: payload.params?.p ?? 1,
  });
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function summarizeApprovalParams(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "";
  }
  const record = value as Record<string, unknown>;
  const keys = [
    "action",
    "channel",
    "target",
    "targets",
    "destination",
    "url",
    "path",
    "filePath",
    "media",
    "command",
  ];
  const lines: string[] = [];
  for (const key of keys) {
    const raw = record[key];
    if (raw === undefined) {
      continue;
    }
    const text =
      typeof raw === "string"
        ? raw
        : typeof raw === "number" || typeof raw === "boolean"
          ? String(raw)
          : "[object]";
    lines.push(`- ${key}: ${text.slice(0, 500)}`);
  }
  return lines.join("\n");
}

function readPendingApprovalPayload(file: string): PendingEgressApprovalPayload {
  return JSON.parse(fs.readFileSync(file, "utf8")) as PendingEgressApprovalPayload;
}

function latestPendingApprovalRequest(requestsDir: string): string | undefined {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(requestsDir, { withFileTypes: true });
  } catch {
    return undefined;
  }
  const pending = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => path.join(requestsDir, entry.name))
    .map((file) => {
      try {
        const payload = readPendingApprovalPayload(file);
        if (payload.status !== "pending") {
          return undefined;
        }
        return {
          file,
          mtimeMs: fs.statSync(file).mtimeMs,
          createdAtMs: payload.createdAt
            ? Number.isFinite(Date.parse(payload.createdAt))
              ? Date.parse(payload.createdAt)
              : 0
            : 0,
        };
      } catch {
        return undefined;
      }
    })
    .filter((entry): entry is { file: string; mtimeMs: number; createdAtMs: number } =>
      Boolean(entry),
    )
    .sort((a, b) => b.createdAtMs - a.createdAtMs || b.mtimeMs - a.mtimeMs);
  return pending[0]?.file;
}

function writeResolvedPendingApprovalRequest(params: {
  file: string;
  request: PendingEgressApprovalPayload;
  status: "approved" | "denied";
  now: Date;
}): PendingEgressApprovalPayload {
  const next = {
    ...params.request,
    status: params.status,
    resolvedBy: "local-cli",
    ...(params.status === "approved"
      ? { approvedAt: params.now.toISOString() }
      : { deniedAt: params.now.toISOString() }),
  };
  fs.writeFileSync(params.file, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(params.file, 0o600);
  return next;
}

export async function resolvePendingEgressApprovalRequest(
  options: ResolvePendingEgressApprovalOptions,
): Promise<ResolvePendingEgressApprovalResult> {
  const requestsDir = resolveEgressApprovalRequestsDir(options.requestsDir);
  const requestFile = options.requestFile?.trim() || latestPendingApprovalRequest(requestsDir);
  if (!requestFile) {
    return {
      ok: false,
      reason: `No pending egress approval request found in ${requestsDir}.`,
    };
  }

  let request: PendingEgressApprovalPayload;
  try {
    request = readPendingApprovalPayload(requestFile);
  } catch {
    return {
      ok: false,
      reason: "Egress approval request could not be read.",
      requestFile,
    };
  }

  if (request.status !== "pending") {
    return {
      ok: false,
      reason: `Egress approval request is not pending (${request.status ?? "missing status"}).`,
      requestFile,
      request,
    };
  }

  const now = options.now ?? new Date();
  if (request.expiresAt && Date.parse(request.expiresAt) <= now.getTime()) {
    return {
      ok: false,
      reason: "Egress approval request expired.",
      requestFile,
      request,
    };
  }

  if (options.decision === "approve") {
    const passwordFile = resolveEgressApprovalPasswordFile(options.passwordFile);
    let payload: PasswordHashPayload;
    try {
      payload = JSON.parse(fs.readFileSync(passwordFile, "utf8")) as PasswordHashPayload;
    } catch {
      return {
        ok: false,
        reason: "Egress approval password is not configured or could not be read.",
        requestFile,
        request,
      };
    }
    let password: string;
    try {
      password = await (options.readPassword ?? readHiddenLine)("Egress approval password: ");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ok: false,
        reason: `Egress approval password required but ${message}.`,
        requestFile,
        request,
      };
    }
    if (!verifyEgressApprovalPassword(password, payload)) {
      return {
        ok: false,
        reason: "Egress approval password verification failed.",
        requestFile,
        request,
      };
    }
  }

  const status = options.decision === "approve" ? "approved" : "denied";
  const resolved = writeResolvedPendingApprovalRequest({
    file: requestFile,
    request,
    status,
    now,
  });
  return {
    ok: true,
    requestFile,
    request: resolved,
    decision: status,
  };
}

function readPendingTimeoutMs(override?: number): number {
  if (typeof override === "number" && Number.isFinite(override) && override > 0) {
    return Math.max(1, Math.floor(override));
  }
  const raw = process.env.OPENCLAW_EGRESS_APPROVAL_TIMEOUT_MS;
  const parsed = raw ? Number(raw) : NaN;
  if (Number.isFinite(parsed) && parsed > 0) {
    return Math.max(1, Math.floor(parsed));
  }
  return DEFAULT_PENDING_TIMEOUT_MS;
}

function writePendingApprovalRequest(params: {
  request: EgressApprovalRequest;
  categories: string;
  paramsSummary: string;
  timeoutMs: number;
}): { id: string; file: string } {
  const id = crypto.randomUUID();
  const requestsDir = resolveEgressApprovalRequestsDir(params.request.requestsDir);
  fs.mkdirSync(requestsDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(requestsDir, 0o700);
  const file = path.join(requestsDir, `${id}.json`);
  const now = Date.now();
  const payload = {
    id,
    status: "pending",
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + params.timeoutMs).toISOString(),
    toolName: params.request.toolName,
    categories: params.categories,
    sessionKey: params.request.sessionKey,
    toolCallId: params.request.toolCallId,
    paramsSummary: params.paramsSummary,
  };
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return { id, file };
}

async function waitForPendingApproval(params: {
  file: string;
  timeoutMs: number;
}): Promise<EgressApprovalResult> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < params.timeoutMs) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    let raw: string;
    try {
      raw = fs.readFileSync(params.file, "utf8");
    } catch {
      return {
        approved: false,
        reason: "Egress approval request disappeared before approval.",
      };
    }
    let payload: { status?: string };
    try {
      payload = JSON.parse(raw) as { status?: string };
    } catch {
      return {
        approved: false,
        reason: "Egress approval request became invalid.",
      };
    }
    if (payload.status === "approved") {
      return { approved: true };
    }
    if (payload.status === "denied") {
      return {
        approved: false,
        reason: "Egress approval denied.",
      };
    }
  }
  return {
    approved: false,
    reason: "Egress approval timed out.",
  };
}

async function requestPendingFileApproval(params: {
  request: EgressApprovalRequest;
  categories: string;
  paramsSummary: string;
}): Promise<EgressApprovalResult> {
  if (isVitest() && process.env.OPENCLAW_EGRESS_APPROVAL_PENDING_TEST_ENABLE !== "1") {
    return {
      approved: false,
      reason: "Egress approval password required but local TTY unavailable.",
    };
  }
  const timeoutMs = readPendingTimeoutMs(params.request.timeoutMs);
  const pending = writePendingApprovalRequest({
    request: params.request,
    categories: params.categories,
    paramsSummary: params.paramsSummary,
    timeoutMs,
  });
  process.stderr.write(
    [
      "Egress approval pending.",
      `- request: ${pending.file}`,
      `- timeoutMs: ${timeoutMs}`,
      "Approve from a trusted local terminal.",
    ].join("\n") + "\n",
  );
  return await waitForPendingApproval({ file: pending.file, timeoutMs });
}

function readHiddenLine(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    const output = process.stderr;
    if (!input.isTTY || !output.isTTY) {
      reject(new Error("local TTY unavailable"));
      return;
    }
    const previousRawMode = input.isRaw;
    let value = "";

    readline.emitKeypressEvents(input);
    input.setRawMode(true);
    output.write(prompt);

    function cleanup() {
      input.off("keypress", onKeypress);
      input.setRawMode(previousRawMode ?? false);
      output.write("\n");
    }

    function onKeypress(char: string | undefined, key: { name?: string; ctrl?: boolean }) {
      if (key?.name === "return" || key?.name === "enter") {
        cleanup();
        resolve(value);
        return;
      }
      if (key?.name === "backspace") {
        value = value.slice(0, -1);
        return;
      }
      if (key?.ctrl && key.name === "c") {
        cleanup();
        reject(new Error("approval cancelled"));
        return;
      }
      if (typeof char === "string") {
        value += char;
      }
    }

    input.on("keypress", onKeypress);
    input.resume();
  });
}

export async function requestEgressApprovalPassword(
  request: EgressApprovalRequest,
): Promise<EgressApprovalResult> {
  if (!shouldRequireEgressApproval(request.toolName)) {
    return { approved: true };
  }
  if (!isEgressApprovalConfigured(request.passwordFile)) {
    return { approved: true };
  }

  const passwordFile = resolveEgressApprovalPasswordFile(request.passwordFile);
  let payload: PasswordHashPayload;
  try {
    payload = JSON.parse(fs.readFileSync(passwordFile, "utf8")) as PasswordHashPayload;
  } catch {
    return {
      approved: false,
      reason: "Egress approval password is configured but could not be read.",
    };
  }

  const categories = classifyGlobalEgressGateTool(request.toolName).join(", ");
  const paramsSummary = summarizeApprovalParams(request.params);
  const details = [
    "Egress approval required:",
    `- tool: ${request.toolName}`,
    `- categories: ${categories}`,
    request.sessionKey ? `- session: ${request.sessionKey}` : undefined,
    request.toolCallId ? `- toolCallId: ${request.toolCallId}` : undefined,
    paramsSummary || undefined,
  ].filter(Boolean);
  process.stderr.write(`${details.join("\n")}\n`);

  let password: string;
  try {
    password = await readHiddenLine("Egress approval password: ");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("local TTY unavailable")) {
      return await requestPendingFileApproval({
        request,
        categories,
        paramsSummary,
      });
    }
    return {
      approved: false,
      reason: `Egress approval password required but ${message}.`,
    };
  }

  if (!verifyEgressApprovalPassword(password, payload)) {
    return {
      approved: false,
      reason: "Egress approval password verification failed.",
    };
  }
  return { approved: true };
}
