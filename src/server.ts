import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { StepSecurityClient } from "./client.js";
import { registerTools } from "./tools/index.js";
import { registerPrompts } from "./prompts/index.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger(config.logLevel);
  const client = new StepSecurityClient(config, logger);

  const server = new McpServer(
    {
      name: "stepsecurity-mcp",
      version: "0.1.0",
    },
    {
      instructions: `You are connected to the StepSecurity MCP server. It exposes tools for investigating supply-chain and CI/CD security incidents against the StepSecurity platform.

When the user mentions a known incident or malicious package by name (e.g. "axios attack", "Shai-Hulud", "trivy compromise"), DO NOT jump straight to npm or baseline searches. Instead:
  1. Call 'list_threat_incidents' for the relevant org to find the matching incident.
  2. Call 'get_threat_incident' to read its 'Am I Affected?' section — this contains the exact compromised package(s) + versions and any C2 IOCs (domains/IPs) you should check.
  3. Only then fan out to the check/search tools based on what the incident says to look for.

For a thorough "am I affected" answer, ALWAYS check BOTH CI and dev machines in parallel — they are independent exposure surfaces. Use the ecosystem-specific pair based on the incident's ecosystem field:
  - ecosystem = 'npm': 'check_npm_package_exposure' + 'check_npm_package_on_dev_machines'
  - ecosystem = 'pypi': 'check_pypi_package_exposure' + 'check_python_package_on_dev_machines'
And regardless of ecosystem, check every IOC the incident lists with 'check_ioc_in_baseline' (or 'find_endpoint_calls_in_tenant' for tenant-wide baseline search).

For a compromised GitHub Action incident, use 'search_action_usage' to find where the action is used, and 'list_suspicious_process_events' / 'list_detections' with detection_id='Action-Uses-Imposter-Commit' for runtime evidence.

When the user asks to browse detections for the tenant (NOT tied to a specific incident) use the dedicated per-type tools. They default to tenant-wide scope and return trimmed, type-specific fields PLUS a dashboard_url deep-link for every detection:
  - 'list_anomalous_network_calls' — outbound calls off the baseline (most common)
  - 'list_blocked_domain_calls' — egress-policy enforcement blocks
  - 'list_https_outbound_calls' — HTTPS call detail (host, method, path)
  - 'list_suspicious_process_events' — runtime compromise signals
  - 'list_secrets_in_build_log' — secret leaks in CI logs (masked)
  - 'list_imposter_commit_detections' — Action pinned to non-tag/non-branch SHA
Use the generic 'list_detections' only for less-common types (source-code-overwritten, harden-runner-config-changed, agent-tampered, etc.).

For a broad "recent detections in my tenant" sweep without a specific type, call ALL SIX dedicated detection tools in parallel and summarise findings grouped by type. Do not skip imposter-commit — it's often the most actionable signal.

Tenant identifier: the 'customer' arg on every detection tool is optional. If omitted, the server falls back to the STEP_SECURITY_CUSTOMER env var. Call 'get_my_tenant' if the user asks what tenant is configured.

When presenting detection results to the user, every detection listed MUST include its dashboard_url as a clickable Markdown link. Format each item as: "- <short description> — [view](<dashboard_url>)". Do not show one link and omit the rest. Do not write "and X more detections" without links — if you truncate, still link the ones you show. If you group detections in a summary (by repo, by type), put the link on each individual item inside the group. A summary without per-detection links is a failure mode: the user cannot triage without clicking through.

Suppression rule workflow — these are WRITE operations that modify the tenant's detection pipeline AND retroactively move matching past detections to suppressed state. Strict protocol:
  1. NEVER call 'create_suppression_rule', 'update_suppression_rule', or 'delete_suppression_rule' without going through this sequence.
  2. For create/update: FIRST call 'preview_suppression_rule' with the same detection_id and conditions. Show the user the 'new_detections_would_suppress' count and the sample list (with dashboard_urls).
  3. Wait for the user to explicitly confirm ("yes, create it" or similar). Do NOT infer confirmation from the user saying "suggest a rule" — that is a request to propose, not to execute.
  4. Only after explicit approval, call the write tool with confirm: true.
  5. For 'analyze anomalous calls' workflows, call 'analyze_anomalous_calls_by_process' first. It groups anomalies by calling process and returns a suggested rule per process. Only VPN / mesh-networking daemons (tailscaled, twingate, zerotier-one, netbird, cloudflared, warp-svc, openvpn, wireguard — flagged with is_vpn_process_candidate: true) are safe to auto-propose as a process-wide rule. Do NOT auto-propose process-wide rules for dockerd, containerd, snapd, curl, kubelet, etc. — those can make security-relevant calls and need per-destination review. A VPN process-wide rule covers both domain AND direct-IP anomalies with a single rule (absent conditions in the rule = wildcards server-side). Note: detections where the agent couldn't attribute a process (tool.name empty) won't be caught by any process-based rule — mention this as a caveat if relevant.
  6. HIGH-RISK DESTINATIONS. Never propose a suppression rule that directly targets 'gist.github.com' or 'gist.githubusercontent.com'. These are commonly abused for payload delivery, exfiltration, and C2; a detection pointing to them is almost always worth investigating, not silencing. If a user asks directly to suppress these, refuse and explain why. If a broader rule (e.g. process-wide) would incidentally suppress detections to these endpoints, the preview tool surfaces that in a 'warnings' array and the analyzer flags it via 'risky_destinations_suppressed_by_process_rule' / 'blocked_reason' — surface those warnings to the user and propose a narrower rule instead, or ask the user to review the risky detections first. Do not create the rule until the risky detections have been explicitly reviewed.

If the user asks what you can do, call 'describe_capabilities'.`,
    },
  );

  registerTools(server, { client, logger, config });
  registerPrompts(server);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("stepsecurity-mcp ready");
}

main().catch((err) => {
  process.stderr.write(
    `fatal: ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(1);
});
