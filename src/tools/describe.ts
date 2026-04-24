import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolContext } from "./index.js";

const CAPABILITIES_TEXT = `StepSecurity MCP server — supply-chain and CI/CD security tooling for StepSecurity customers.

Scenarios supported today:

1. Respond to a threat-center incident
   - list_threat_incidents — browse recent supply-chain incidents for an org
   - get_threat_incident — full incident detail incl. "Am I Affected?" markdown

2. Check if you're affected by a malicious package (npm or PyPI)
   - check_npm_package_exposure / check_pypi_package_exposure — org-wide: scans monitored repos
     (PRs, default branches, workflow runs). Pick by incident.ecosystem.
   - check_npm_package_on_dev_machines / check_python_package_on_dev_machines — developer machines
     via Dev Machine Guard.

3. Check if an IOC (domain or IP) was contacted
   - check_ioc_in_baseline — searches the Harden-Runner org baseline for observed endpoints matching the indicator (single org)
   - find_endpoint_calls_in_tenant — same check but tenant-wide: fans out across every GitHub org installed under the customer and returns a flat list of per-job observations

4. Respond to a compromised GitHub Action
   - search_action_usage — find every workflow in the org that uses a given Action

5. Browse Harden-Runner detections across the tenant (all orgs installed under the customer).
   Each tool returns results with a dashboard_url deep-link for click-through.
   - list_anomalous_network_calls — outbound calls to endpoints NOT in the repo baseline (most-used)
   - list_blocked_domain_calls — egress-policy enforcement actively blocked a call
   - list_https_outbound_calls — HTTPS calls with method + path visibility
   - list_suspicious_process_events — memory-reads, reverse shells, privileged containers
   - list_secrets_in_build_log — secret detections in CI logs (API returns masked secrets)
   - list_imposter_commit_detections — Action pinned to a SHA that's not any known tag/branch
   - list_detections — generic escape hatch for less-common detection types (source-code
     overwritten, HardenRunner config changed, agent tampered, etc.)

6. Audit and inventory queries
   - list_recent_workflow_runs — list the 100 most recent Harden-Runner-monitored workflow runs for an org (or one repo). Call this to discover a run_id when the user says "the latest run" / "yesterday's run" without giving an explicit ID.
   - list_github_api_calls_in_run — list every github.com / api.github.com call made by a specific workflow run, grouped by job. Chain after list_recent_workflow_runs if the run_id isn't known.
   - find_repos_using_endpoint — find every repo in an org whose baseline contains a given endpoint (fans out per repo, 10–60s on large orgs). Single-org; compose with list_tenant_github_orgs for tenant-wide sweeps.
   - list_tenant_github_orgs — list every GitHub org installed under the tenant. Use this as the first step of a tenant-wide audit.

7. Triage detections and suppress false positives (WRITE — admin API key required)
   - analyze_anomalous_calls_by_process — tenant-wide: groups anomalous calls by calling process,
     flags VPN / mesh-networking daemons (tailscaled, twingate, zerotier-one, netbird, cloudflared,
     warp-svc, openvpn, wireguard) as strong candidates for a single process-scoped rule. One such
     rule covers both domain and direct-IP anomalies for that process.
   - list_suppression_rules / get_suppression_rule — inspect existing rules.
   - preview_suppression_rule — APPROXIMATE client-side dry-run: shows which existing detections
     the proposed rule would match (count + up to 20 samples with dashboard links). Call this
     before any write.
   - create_suppression_rule — create a rule. Requires confirm: true. Server retroactively
     suppresses matching past detections. Response reports how many past detections were moved.
   - update_suppression_rule / delete_suppression_rule — same confirm-true safety.
   Workflow: analyze_anomalous_calls_by_process → pick a process → preview → user approves → create.

8. Tenant identity
   - get_my_tenant — report the configured STEP_SECURITY_CUSTOMER default.

The 'customer' argument on every detection tool is optional. If the user set STEP_SECURITY_CUSTOMER
in their MCP config, the server uses that by default and tools can be called with zero args.

Typical investigation flow for an incident (e.g. a malicious npm release):
  1. list_threat_incidents → find the incident id
  2. get_threat_incident → read the "Am I Affected?" section to extract package names, versions, and IOCs
  3. In parallel: check_npm_package_exposure, check_npm_package_on_dev_machines, check_ioc_in_baseline
  4. Report back with concrete matches (repo, dev machine, workflow run) so the user can remediate.

For a compromised Action (e.g. trivy): search_action_usage to list affected workflows,
then list_detections with Action-Uses-Imposter-Commit and Suspicious-Process-Events to see runtime evidence.`;

export function registerDescribeTool(server: McpServer, _ctx: ToolContext): void {
  server.tool(
    "describe_capabilities",
    "Describe what this MCP server can do and how to use it. Call this when the user asks 'what can you do?', 'what does this server support?', or is otherwise unsure how to start.",
    {},
    async () => ({ content: [{ type: "text", text: CAPABILITIES_TEXT }] }),
  );
}
