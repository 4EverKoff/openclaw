import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach } from "vitest";
import { describe, expect, it } from "vitest";
import { collectMinimalProfileOverrideFindings } from "./audit-extra.sync.js";
import { collectElevatedFindings, collectGlobalEgressGateFindings } from "./audit.js";

const tempDirs: string[] = [];

function writeEgressApprovalPasswordFile(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-audit-egress-"));
  tempDirs.push(dir);
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync("test-password", salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
  });
  const file = path.join(dir, "egress-approval-password.json");
  fs.writeFileSync(
    file,
    JSON.stringify({
      algorithm: "scrypt",
      params: { N: 16384, r: 8, p: 1, keyLength: 64 },
      salt: salt.toString("base64"),
      hash: hash.toString("base64"),
    }),
  );
  return file;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("security audit config basics", () => {
  it("flags agent profile overrides when global tools.profile is minimal", () => {
    const findings = collectMinimalProfileOverrideFindings({
      tools: {
        profile: "minimal",
      },
      agents: {
        list: [
          {
            id: "owner",
            tools: { profile: "full" },
          },
        ],
      },
    });

    expect(
      findings.some(
        (finding) =>
          finding.checkId === "tools.profile_minimal_overridden" && finding.severity === "warn",
      ),
    ).toBe(true);
  });

  it("flags tools.elevated allowFrom wildcard as critical", () => {
    const findings = collectElevatedFindings({
      tools: {
        elevated: {
          allowFrom: { whatsapp: ["*"] },
        },
      },
    });

    expect(
      findings.some(
        (finding) =>
          finding.checkId === "tools.elevated.allowFrom.whatsapp.wildcard" &&
          finding.severity === "critical",
      ),
    ).toBe(true);
  });

  it("warns when global egress gate password or plugin allowlist is missing", () => {
    const findings = collectGlobalEgressGateFindings({
      cfg: { plugins: { enabled: true } },
      env: { OPENCLAW_EGRESS_APPROVAL_PASSWORD_FILE: "/tmp/missing-egress-password.json" },
    });

    expect(
      findings.some(
        (finding) =>
          finding.checkId === "global_egress_gate.password_missing" && finding.severity === "warn",
      ),
    ).toBe(true);
    expect(
      findings.some(
        (finding) =>
          finding.checkId === "global_egress_gate.plugins_allow_missing" &&
          finding.severity === "warn",
      ),
    ).toBe(true);
  });

  it("does not warn when global egress gate password and plugin allowlist are configured", () => {
    const passwordFile = writeEgressApprovalPasswordFile();

    const findings = collectGlobalEgressGateFindings({
      cfg: { plugins: { enabled: true, allow: ["trusted-plugin"] } },
      env: { OPENCLAW_EGRESS_APPROVAL_PASSWORD_FILE: passwordFile },
    });

    expect(findings.map((finding) => finding.checkId)).not.toContain(
      "global_egress_gate.password_missing",
    );
    expect(findings.map((finding) => finding.checkId)).not.toContain(
      "global_egress_gate.plugins_allow_missing",
    );
  });
});
