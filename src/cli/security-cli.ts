import type { Command } from "commander";
import { getRuntimeConfig } from "../config/config.js";
import { defaultRuntime } from "../runtime.js";
import { runSecurityAudit } from "../security/audit.js";
import {
  resolvePendingEgressApprovalRequest,
  type ResolvePendingEgressApprovalResult,
} from "../security/egress-approval-password.js";
import { fixSecurityFootguns } from "../security/fix.js";
import { normalizeOptionalString } from "../shared/string-coerce.js";
import { formatDocsLink } from "../terminal/links.js";
import { isRich, theme } from "../terminal/theme.js";
import { shortenHomeInString, shortenHomePath } from "../utils.js";
import { formatCliCommand } from "./command-format.js";
import { resolveCommandSecretRefsViaGateway } from "./command-secret-gateway.js";
import { getSecurityAuditCommandSecretTargetIds } from "./command-secret-targets.js";
import { formatHelpExamples } from "./help-format.js";

type SecurityAuditOptions = {
  json?: boolean;
  deep?: boolean;
  fix?: boolean;
  token?: string;
  password?: string;
};

type EgressApprovalCliOptions = {
  json?: boolean;
  passwordFile?: string;
  requestsDir?: string;
};

function formatSummary(summary: { critical: number; warn: number; info: number }): string {
  const rich = isRich();
  const c = summary.critical;
  const w = summary.warn;
  const i = summary.info;
  const parts: string[] = [];
  parts.push(rich ? theme.error(`${c} critical`) : `${c} critical`);
  parts.push(rich ? theme.warn(`${w} warn`) : `${w} warn`);
  parts.push(rich ? theme.muted(`${i} info`) : `${i} info`);
  return parts.join(" · ");
}

function formatEgressApprovalResult(
  result: Extract<ResolvePendingEgressApprovalResult, { ok: true }>,
): string {
  const rich = isRich();
  const heading = rich ? theme.heading("Egress approval") : "Egress approval";
  const status =
    result.decision === "approved"
      ? rich
        ? theme.success("approved")
        : "approved"
      : rich
        ? theme.warn("denied")
        : "denied";
  const lines = [
    heading,
    `Status: ${status}`,
    `Request: ${shortenHomePath(result.requestFile)}`,
    result.request.toolName ? `Tool: ${result.request.toolName}` : undefined,
    result.request.categories ? `Categories: ${result.request.categories}` : undefined,
    result.request.sessionKey ? `Session: ${result.request.sessionKey}` : undefined,
    result.request.toolCallId ? `Tool call: ${result.request.toolCallId}` : undefined,
  ].filter(Boolean);
  return lines.join("\n");
}

async function runEgressApprovalDecision(
  decision: "approve" | "deny",
  requestFile: string | undefined,
  opts: EgressApprovalCliOptions,
) {
  const result = await resolvePendingEgressApprovalRequest({
    decision,
    requestFile,
    passwordFile: opts.passwordFile,
    requestsDir: opts.requestsDir,
  });

  if (opts.json) {
    defaultRuntime.writeJson(result, 0);
    if (!result.ok) {
      process.exitCode = 1;
    }
    return;
  }

  if (!result.ok) {
    throw new Error(result.reason);
  }

  defaultRuntime.log(formatEgressApprovalResult(result));
}

export function registerSecurityCli(program: Command) {
  const security = program
    .command("security")
    .description("Audit local config and state for common security foot-guns")
    .addHelpText(
      "after",
      () =>
        `\n${theme.heading("Examples:")}\n${formatHelpExamples([
          ["openclaw security audit", "Run a local security audit."],
          [
            "openclaw security audit --deep",
            "Include best-effort live Gateway probes and plugin-owned security audit collectors.",
          ],
          ["openclaw security audit --deep --token <token>", "Use explicit token for deep probe."],
          [
            "openclaw security audit --deep --password <password>",
            "Use explicit password for deep probe.",
          ],
          ["openclaw security audit --fix", "Apply safe remediations and file-permission fixes."],
          ["openclaw security audit --json", "Output machine-readable JSON."],
          [
            "openclaw security egress-approval approve",
            "Approve newest pending egress request after local password verification.",
          ],
          [
            "openclaw security egress-approval deny <request-file>",
            "Deny a specific pending egress request.",
          ],
        ])}\n\n${theme.muted("Docs:")} ${formatDocsLink("/cli/security", "docs.openclaw.ai/cli/security")}\n`,
    );

  security
    .command("audit")
    .description("Audit config + local state for common security foot-guns")
    .option("--deep", "Attempt live Gateway probes and plugin-owned collector checks", false)
    .option("--token <token>", "Use explicit gateway token for deep probe auth")
    .option("--password <password>", "Use explicit gateway password for deep probe auth")
    .option("--fix", "Apply safe fixes (tighten defaults + chmod state/config)", false)
    .option("--json", "Print JSON", false)
    .action(async (opts: SecurityAuditOptions) => {
      const token = normalizeOptionalString(opts.token);
      const password = normalizeOptionalString(opts.password);
      const fixResult = opts.fix ? await fixSecurityFootguns().catch((_err) => null) : null;

      const sourceConfig = getRuntimeConfig();
      const { resolvedConfig: cfg, diagnostics: secretDiagnostics } =
        await resolveCommandSecretRefsViaGateway({
          config: sourceConfig,
          commandName: "security audit",
          targetIds: getSecurityAuditCommandSecretTargetIds(),
          mode: "read_only_status",
        });
      const report = await runSecurityAudit({
        config: cfg,
        sourceConfig,
        deep: Boolean(opts.deep),
        includeFilesystem: true,
        includeChannelSecurity: true,
        deepProbeAuth:
          token || password
            ? { ...(token ? { token } : {}), ...(password ? { password } : {}) }
            : undefined,
      });

      if (opts.json) {
        defaultRuntime.writeJson(
          fixResult
            ? { fix: fixResult, report, secretDiagnostics }
            : { ...report, secretDiagnostics },
        );
        return;
      }

      const rich = isRich();
      const heading = (text: string) => (rich ? theme.heading(text) : text);
      const muted = (text: string) => (rich ? theme.muted(text) : text);

      const lines: string[] = [];
      lines.push(heading("OpenClaw security audit"));
      lines.push(muted(`Summary: ${formatSummary(report.summary)}`));
      lines.push(muted(`Run deeper: ${formatCliCommand("openclaw security audit --deep")}`));
      for (const diagnostic of secretDiagnostics) {
        lines.push(muted(`[secrets] ${diagnostic}`));
      }

      if (opts.fix) {
        lines.push(muted(`Fix: ${formatCliCommand("openclaw security audit --fix")}`));
        if (!fixResult) {
          lines.push(muted("Fixes: failed to apply (unexpected error)"));
        } else if (
          fixResult.errors.length === 0 &&
          fixResult.changes.length === 0 &&
          fixResult.actions.every((a) => !a.ok)
        ) {
          lines.push(muted("Fixes: no changes applied"));
        } else {
          lines.push("");
          lines.push(heading("FIX"));
          for (const change of fixResult.changes) {
            lines.push(muted(`  ${shortenHomeInString(change)}`));
          }
          for (const action of fixResult.actions) {
            if (action.kind === "chmod") {
              const mode = action.mode.toString(8).padStart(3, "0");
              if (action.ok) {
                lines.push(muted(`  chmod ${mode} ${shortenHomePath(action.path)}`));
              } else if (action.skipped) {
                lines.push(
                  muted(`  skip chmod ${mode} ${shortenHomePath(action.path)} (${action.skipped})`),
                );
              } else if (action.error) {
                lines.push(
                  muted(`  chmod ${mode} ${shortenHomePath(action.path)} failed: ${action.error}`),
                );
              }
              continue;
            }
            const command = shortenHomeInString(action.command);
            if (action.ok) {
              lines.push(muted(`  ${command}`));
            } else if (action.skipped) {
              lines.push(muted(`  skip ${command} (${action.skipped})`));
            } else if (action.error) {
              lines.push(muted(`  ${command} failed: ${action.error}`));
            }
          }
          if (fixResult.errors.length > 0) {
            for (const err of fixResult.errors) {
              lines.push(muted(`  error: ${shortenHomeInString(err)}`));
            }
          }
        }
      }

      const bySeverity = (sev: "critical" | "warn" | "info") =>
        report.findings.filter((f) => f.severity === sev);

      const render = (sev: "critical" | "warn" | "info") => {
        const list = bySeverity(sev);
        if (list.length === 0) {
          return;
        }
        const label =
          sev === "critical"
            ? rich
              ? theme.error("CRITICAL")
              : "CRITICAL"
            : sev === "warn"
              ? rich
                ? theme.warn("WARN")
                : "WARN"
              : rich
                ? theme.muted("INFO")
                : "INFO";
        lines.push("");
        lines.push(heading(label));
        for (const f of list) {
          lines.push(`${theme.muted(f.checkId)} ${f.title}`);
          lines.push(`  ${f.detail}`);
          if (f.remediation?.trim()) {
            lines.push(`  ${muted(`Fix: ${f.remediation.trim()}`)}`);
          }
        }
      };

      render("critical");
      render("warn");
      render("info");

      defaultRuntime.log(lines.join("\n"));
    });

  const egressApproval = security
    .command("egress-approval")
    .description("Approve or deny pending egress approval requests")
    .addHelpText(
      "after",
      () =>
        `\n${theme.heading("Examples:")}\n${formatHelpExamples([
          [
            "openclaw security egress-approval approve",
            "Approve newest pending request after local password verification.",
          ],
          [
            "openclaw security egress-approval approve ~/.openclaw/security/egress-approval-requests/<id>.json",
            "Approve a specific request file.",
          ],
          [
            "openclaw security egress-approval deny ~/.openclaw/security/egress-approval-requests/<id>.json",
            "Deny a specific request.",
          ],
        ])}\n`,
    );

  egressApproval
    .command("approve [requestFile]")
    .description("Approve a pending egress request after local password verification")
    .option("--password-file <path>", "Use a specific egress approval password hash file")
    .option("--requests-dir <path>", "Use a specific pending egress approval requests directory")
    .option("--json", "Print JSON", false)
    .action((requestFile: string | undefined, opts: EgressApprovalCliOptions) =>
      runEgressApprovalDecision("approve", requestFile, opts),
    );

  egressApproval
    .command("deny [requestFile]")
    .description("Deny a pending egress request")
    .option("--requests-dir <path>", "Use a specific pending egress approval requests directory")
    .option("--json", "Print JSON", false)
    .action((requestFile: string | undefined, opts: EgressApprovalCliOptions) =>
      runEgressApprovalDecision("deny", requestFile, opts),
    );
}
