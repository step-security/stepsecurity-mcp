# stepsecurity-mcp

Model Context Protocol (MCP) server for the [StepSecurity](https://www.stepsecurity.io) platform. Exposes a curated set of StepSecurity APIs as LLM-callable tools so you can investigate supply-chain and CI/CD security issues in plain English from Claude Desktop, Claude Code, Cursor, or any other MCP client.

> Status: early WIP. Private repo; will be open-sourced once the tool surface stabilizes.

## Requirements

- Node.js 22+
- A StepSecurity API key
- Your StepSecurity customer/tenant identifier (see [Configure](#configure))

## Install

No install needed for most users — wire the published package into your MCP client via `npx` (see [Wire into an MCP client](#wire-into-an-mcp-client) below). `npx` will fetch `@stepsecurity/stepsecurity-mcp` from npm on first run.

To hack on the server locally instead:

```bash
git clone git@github.com:step-security/stepsecurity-mcp.git
cd stepsecurity-mcp
npm install
npm run build
```

## Configure

### Get an API key

Go to the StepSecurity admin console for your tenant and create a key:

```
https://app.stepsecurity.io/<tenant>/admin-console/integrations/stepsecurity-api
```

Replace `<tenant>` with your StepSecurity tenant name (the same value you'll put in `STEP_SECURITY_CUSTOMER`).

StepSecurity supports **read-only tenant API keys** — recommended for this MCP server since every tool shipped here is read-only (list / get / search). Use a read-only key unless you have a specific reason to grant write access.

### Env vars

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `STEP_SECURITY_API_KEY` | yes | — | Your API key. Sent as `Authorization: Bearer <key>`. A read-only key is sufficient. |
| `STEP_SECURITY_CUSTOMER` | strongly recommended | — | Your tenant identifier. When set, `customer` is optional on every tool call. |
| `LOG_LEVEL` | no | `info` | `debug` / `info` / `warn` / `error`. Logs go to stderr. |

Copy `.env.example` to `.env` for manual runs. For MCP clients, set the same values via the `env` block of the client config (next section).

## Wire into an MCP client

### Claude Code

Add to your project's `.mcp.json` (or user-level `~/.claude.json`):

```json
{
  "mcpServers": {
    "stepsecurity": {
      "command": "npx",
      "args": ["-y", "@stepsecurity/stepsecurity-mcp"],
      "env": {
        "STEP_SECURITY_API_KEY": "${STEP_SECURITY_API_KEY}",
        "STEP_SECURITY_CUSTOMER": "your-tenant-name"
      }
    }
  }
}
```

If you're developing locally, swap `command` to `node` and `args` to `["/absolute/path/to/stepsecurity-mcp/dist/server.js"]`.

Restart, then run `/mcp` to confirm the server connected.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) with the same shape, then restart Claude Desktop.

### MCP Inspector (no-LLM debugging)

Fastest iteration loop — browse the tool list, fill args, see raw JSON-RPC:

```bash
STEP_SECURITY_API_KEY=... STEP_SECURITY_CUSTOMER=... npm run inspect
```

Opens a web UI at `http://localhost:6274`.

---

## Scenarios

The LLM chains multiple tool calls from one prompt — you don't need to know tool names. Ask any of the following in natural language:

### 1. Respond to a supply-chain incident

You heard about a malicious npm release or a compromised Action. Ask whether your tenant is affected. The LLM will: pull the incident from StepSecurity's threat center → read its "Am I Affected?" section → fan out to CI exposure, developer machines, and baseline IOC checks in parallel.

Try:
- *"Am I affected by the axios supply-chain incident?"* (npm)
- *"Check exposure for the xinference PyPI compromise."* (pypi)
- *"Check exposure for the trivy compromise."* (compromised GitHub Action)
- *"There's a new malicious release mentioned on HN — anything in our threat center matching?"*

Tools used behind the scenes: `list_threat_incidents`, `get_threat_incident`, and per-ecosystem exposure tools (`check_npm_package_exposure` + `check_npm_package_on_dev_machines` for npm, `check_pypi_package_exposure` + `check_python_package_on_dev_machines` for pypi), plus `check_ioc_in_baseline` / `find_endpoint_calls_in_tenant` for C2 indicators and `search_action_usage` for compromised Actions.

There's also a slash-prompt you can invoke explicitly in Claude Desktop: **am-i-affected** *(args: org, incident)* — expands into a guaranteed step-by-step investigation plan.

### 2. Browse recent detections in your tenant

Tenant-wide sweep of Harden-Runner detections across every org installed under your customer. Every detection returned includes a `dashboard_url` deep-link to the exact tab on the run page so you can click through to investigate.

Try:
- *"What are the recent detections in StepSecurity for my tenant?"* — sweeps all six detection types in parallel.
- *"Show me any anomalous network calls."*
- *"Were any secrets leaked in build logs?"*
- *"Which domains got blocked this week?"*
- *"Any imposter-commit detections I should look at?"*

One tool per common detection type, all defaulting to tenant scope:

| Tool | Detection type | Links to |
|---|---|---|
| `list_anomalous_network_calls` | New outbound calls off the baseline | `tab=network-events` |
| `list_blocked_domain_calls` | Egress-policy blocks | `tab=network-events` |
| `list_https_outbound_calls` | HTTPS calls with method + path | `tab=network-events` |
| `list_suspicious_process_events` | Memory-read, reverse-shell, privileged container | `tab=process-events` |
| `list_imposter_commit_detections` | Action pinned to a non-tag/non-branch SHA | `tab=process-events` |
| `list_secrets_in_build_log` | Secret patterns in CI logs (masked) | `tab=controls` |
| `list_detections` | Generic escape hatch for less-common types (source-code overwritten, harden-runner-config-changed, agent-tampered, etc.) | — |

### 3. Check a specific IOC

You have a domain or IP (e.g. from a threat feed) and want to know if any workflow contacted it.

Try:
- *"Was the C2 domain `sfrclak.com` seen in our Harden-Runner baseline?"* (single org)
- *"Did any job across our tenant contact `registry.npmjs.org`?"* (tenant-wide)
- *"Which workflow runs hit `142.11.206.73`?"*

Tools:
- `check_ioc_in_baseline(owner, indicator)` — single org, server-side substring match. Each observation has a `dashboard_url` linking to the run's network-events tab.
- `find_endpoint_calls_in_tenant(endpoint, customer?)` — tenant-wide. Lists orgs then fans out per org with bounded concurrency. Returns a flat list of `{org, repo, workflow, job, run_id, timestamp, dashboard_url}` observations.

### 4. Audit usage of a specific GitHub Action

Triage when an Action is reported compromised.

Try:
- *"Which workflows use `aquasecurity/trivy-action`?"*
- *"Where is `tj-actions/changed-files` referenced across our repos?"*

Tool: `search_action_usage` (returns per-workflow pinning detail + upstream release info).

### 5. Audit GitHub API calls a workflow run made

You want to see every `github.com` / `api.github.com` call a specific run touched — catching writes to repos outside the org, surprising cross-org access, or API calls from third-party Actions.

Try:
- *"What GitHub API calls did the latest run of `trivy-scan` in `<org>/<repo>` make?"*
- *"Audit the API footprint of the most recent CI run in `<org>/<repo>`."*
- *"For run 23336327796 of `<org>/<repo>`, which GitHub API endpoints were called?"*

Tools: `list_recent_workflow_runs(owner, repo?)` to find the run ID (when the user doesn't give one), then `list_github_api_calls_in_run(owner, repo, runId)` — single upstream call, grouped by job with step/tool attribution. The LLM will chain the two automatically if you phrase the question as "the latest run" or "yesterday's run".

### 6. Find every repo in an org contacting a given endpoint

You want to answer inventory / migration questions: "who still uses `registry.npmjs.org`?", "which repos contact `bun.sh`?".

Try:
- *"Which repos in `<org>` contact `bun.sh`?"*
- *"Find all repos still calling `registry.npmjs.org`."*

Tool: `find_repos_using_endpoint(owner, endpoint, concurrency?)` — fans out one baseline query per repo with bounded parallelism (default 10 in flight). Tens of seconds on large orgs. Returns only the matching repos, each with a baseline deep-link.

For a **tenant-wide** sweep across every org installed under your customer, first call `list_tenant_github_orgs` (takes `customer` optionally, falls back to `STEP_SECURITY_CUSTOMER`) to get the org list, then run `find_repos_using_endpoint` per org. The LLM will compose these when you ask something like *"which repos across our tenant still use `registry.npmjs.org`?"*.

> `find_repos_using_endpoint` (org-wide, repo-attributed) vs `check_ioc_in_baseline` (single org, flat endpoint list): use the former when you want a per-repo inventory, the latter for quick IOC triage.

### 7. Triage detections and add suppression rules (write)

You want to analyze past detections — most often anomalous outbound network calls — decide which are false positives, and suppress them at the right scope. The LLM proposes rules, shows you the impact before anything writes, and only executes after you say yes.

Try:
- *"Analyze anomalous network calls across our tenant and suggest suppression rules for false positives."*
- *"Suppress anomalous calls to `registry.npmjs.org` from the `npm-install` job in org `my-org`."*
- *"Show me all suppression rules configured for our tenant."*

Tools (read):
- `analyze_anomalous_calls_by_process` — tenant-wide: groups anomalies by calling process, flags **VPN / mesh-networking daemons** (tailscaled, twingate, zerotier-one, netbird, cloudflared, warp-svc, openvpn, wireguard) as strong candidates for a single process-scoped rule. One such rule matches both domain and direct-IP anomalies from that process (rule conditions without `endpoint` or `ip_address` act as wildcards server-side). Other processes (dockerd, containerd, snapd, curl, kubelet, etc.) are returned too but not flagged — they deserve per-destination review.
- `list_suppression_rules`, `get_suppression_rule`
- `preview_suppression_rule(detectionId, conditions)` — approximate client-side dry-run. Returns the detections that would be suppressed (count + sample with dashboard links).

Tools (write — require `confirm: true` and an admin-scoped API key):
- `create_suppression_rule` — creates the rule. Server retroactively suppresses matching past detections synchronously; tool reports how many were moved.
- `update_suppression_rule`, `delete_suppression_rule`.

> **Never-suppress list:** `gist.github.com` and `gist.githubusercontent.com` are commonly used by attackers for payload delivery and exfiltration. The tools will refuse to create a rule that directly targets these hosts, and `preview_suppression_rule` will flag a warning if a broader rule would incidentally silence calls to them.
> **Scope matters for auth:** tenant-wide rules (`conditions.owner = "*"`) require tenant admin. Org-level rules (`owner = "<org>"`, `repo = "*"`) require admin on that org. If you get `403`, the tool surfaces a clear message explaining to swap to an admin key or narrow the scope.
> **Severity:** only `ignore` (pure suppression) is supported in the backend; the tool hardcodes it.
> **Deletion doesn't un-suppress.** Detections already moved to suppressed state stay that way after the rule is deleted.

### 8. Confirm your configured tenant

When in doubt about which tenant the tools are hitting.

Try:
- *"What's my tenant?"*
- *"Which customer is this MCP server scoped to?"*

Tool: `get_my_tenant` (reports the configured `STEP_SECURITY_CUSTOMER` and links to the tenant admin console).

---

## Tool reference (all tools)

Grouped by area. Run `describe_capabilities` from the LLM for a self-describing summary.

- **Meta** — `describe_capabilities`, `ping`, `get_my_tenant`
- **Threat center** — `list_threat_incidents`, `get_threat_incident`
- **Exposure checks** — `check_npm_package_exposure`, `check_npm_package_on_dev_machines`, `check_pypi_package_exposure`, `check_python_package_on_dev_machines`, `check_ioc_in_baseline`, `find_endpoint_calls_in_tenant`, `search_action_usage`
- **Detection browsers (tenant-wide)** — `list_anomalous_network_calls`, `list_blocked_domain_calls`, `list_https_outbound_calls`, `list_suspicious_process_events`, `list_imposter_commit_detections`, `list_secrets_in_build_log`, `list_detections`
- **Auditing / inventory** — `list_recent_workflow_runs`, `list_github_api_calls_in_run`, `find_repos_using_endpoint`, `list_tenant_github_orgs`
- **Suppression rules (write)** — `list_suppression_rules`, `get_suppression_rule`, `preview_suppression_rule`, `analyze_anomalous_calls_by_process`, `create_suppression_rule`, `update_suppression_rule`, `delete_suppression_rule`

## Development

```bash
npm run dev        # watch mode with tsx
npm run typecheck
npm run test
npm run build
```

## Project layout

```
src/
  server.ts        MCP bootstrap (stdio transport) + server-level instructions
  config.ts        env loading (API key, customer, dashboard host)
  logger.ts        stderr-only JSON logger (stdout is reserved for JSON-RPC)
  client.ts        thin fetch wrapper with Bearer-auth injection
  tools/
    index.ts       tool registry
    describe.ts    describe_capabilities
    tenant.ts      get_my_tenant
    threat-center.ts   incident + exposure-check tools
    detections.ts  per-type detection browsers (+ dashboard deep-links)
    ping.ts
  prompts/
    index.ts       am-i-affected slash-prompt
```
