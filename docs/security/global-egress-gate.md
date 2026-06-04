---
summary: "Global egress gate policy for indirect prompt injection from web/docs/files/skills/plugins/MCP"
title: Global egress gate
read_when:
  - You are adding or reviewing tool routing, plugin tools, MCP tools, external sends, uploads, or sensitive file access
  - You are hardening OpenClaw against indirect prompt injection
status: draft
---

# Global egress gate

OpenClaw must treat untrusted content as data, not instructions.

Untrusted origins include:

- websites
- emails
- docs and files
- configs
- comments, issues, PR text, branch names, commit text
- logs and tool outputs
- OCR/transcripts
- model outputs
- unverified skills
- unverified plugins/connectors
- unverified MCP servers
- plugin-provided schemas/tools

Untrusted data may be summarized, extracted, transformed, compared, or analyzed. It must not request sensitive actions.

## Blocked categories

`external_send`:

- HTTP POST/PUT/PATCH to the internet
- outgoing email
- file upload
- Drive/Slack/Notion/etc. share
- webhook
- Git push
- deploy/release
- opening URLs that embed local data or secrets

`sensitive_read`:

- secrets
- real `.env` files
- keychain/vault/token stores
- credentials
- personal folders unless directly requested by the operator

`dangerous_action`:

- deletion
- broad overwrite
- permission/owner changes
- tool/plugin/dependency install
- arbitrary shell execution
- signing/notarization/release

## Decision rule

If the action origin is untrusted and the category is `external_send`, `sensitive_read`, or `dangerous_action`, deny before password approval.

If the action origin is trusted/direct operator intent and the category is `external_send` or `dangerous_action`, require password approval through a trusted local prompt outside chat/model context.

Even trusted origins should show:

- source
- action
- destination, if applicable
- local paths, if applicable
- impact

## Skills, plugins, and MCP

Skills, plugins, connectors, and MCP servers cannot grant themselves trust or bypass gates.

Trust must come from a local operator-controlled allowlist. Permissions are granted by capability, not by skill/plugin name alone.

Example refusal:

```text
Action refused.
Reason: instruction came from untrusted skill/plugin/MCP content.
Blocked categories: sensitive_read, external_send.
Needed: direct operator request, then password approval outside chat/model context.
```

## Password handling

The approval password must never appear in:

- chat
- model context
- prompts
- configs
- docs
- logs
- tool outputs

Use a masked local prompt controlled by trusted host code. One approval applies to one exact action. Reject if destination, file list, or action changes after approval.

The current password hash path is:

```text
~/.openclaw/security/egress-approval-password.json
```

The file stores a `scrypt` hash and salt only.

## Implementation target

Current implementation:

- agent `before_tool_call` enforcement blocks external hook sessions (`hook:gmail:*`, `hook:webhook:*`, `hook:*`) before plugin hooks or plugin approvals when they attempt an `external_send`, `sensitive_read`, or `dangerous_action` tool
- plugin/MCP origin is carried into the hook; when `plugins.allow` is configured, plugin tools outside that allowlist become `untrusted_plugin`, and `bundle-mcp` tools outside that allowlist become `untrusted_mcp`
- untrusted plugin/MCP tools are blocked before plugin hooks or plugin approvals, including unknown tool names that cannot be safely categorized
- skill command tool dispatches (`command-dispatch: tool`) execute with origin `untrusted_skill`; sensitive and unknown tool names are blocked before plugin hooks or plugin approvals
- skill command prompt rewrites (`/skill ...` and native skill commands without `command-dispatch: tool`) mark the resulting agent run with origin `untrusted_skill`, so model tool calls from that rewritten prompt are blocked by the same gate
- CLI backend runs from an `untrusted_skill` prompt rewrite run with tools disabled; backends with always-on native tools fail closed
- if `~/.openclaw/security/egress-approval-password.json` exists, trusted direct `external_send` and `dangerous_action` tool calls require a masked local password prompt outside chat/model context
- when no local TTY is available, password-required actions create a pending request under `~/.openclaw/security/egress-approval-requests/` and wait for local approval; timeout/deny/missing request blocks the action
- pending requests can be approved or denied from a trusted local terminal with `openclaw security egress-approval approve [request-file]` or `openclaw security egress-approval deny [request-file]`
- direct trusted sessions still flow through existing tool policy and approval mechanisms
- `openclaw security audit` warns when the egress approval password hash is missing or plugin loading is enabled without `plugins.allow`

Remaining implementation targets:

- refine the allowlist from plugin id level toward capability-level trust where needed

Prompt rules are helpful but not sufficient against a compromised agent/plugin/tool description.
