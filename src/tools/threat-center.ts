import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolContext } from "./index.js";
import { DASHBOARD_HOST } from "../config.js";

interface ThreatIntelIncident {
  id: string;
  title: string;
  description?: string;
  details?: string;
  ecosystem?: string;
  package_name?: string | null;
  affected_versions?: string | null;
  severity?: string;
  is_active?: string;
  cve?: string | null;
  cve_link?: string | null;
  incident_start_time?: string;
  incident_end_time?: string | null;
  created_at?: string;
  updated_at?: string;
}

interface ListIncidentsResponse {
  detections: ThreatIntelIncident[];
  pagination?: { current_page?: string; limit?: string };
}

interface GetIncidentResponse {
  detections: ThreatIntelIncident | ThreatIntelIncident[];
}

function textJson(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function compactIncident(i: ThreatIntelIncident) {
  return {
    id: i.id,
    title: i.title,
    severity: i.severity,
    ecosystem: i.ecosystem,
    package_name: i.package_name,
    affected_versions: i.affected_versions,
    is_active: i.is_active,
    cve: i.cve,
    started_at: i.incident_start_time,
    ended_at: i.incident_end_time,
  };
}

export function registerThreatCenterTools(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "list_threat_incidents",
    "List supply-chain threat-center incidents tracked by StepSecurity for a GitHub organization. ALWAYS call this first when the user mentions a known supply-chain incident or malicious package by name (e.g. 'axios compromise', 'trivy incident', 'Shai-Hulud') to find the matching incident and its ID before searching for exposure. Returns a compact summary (no markdown body) — then call get_threat_incident with the ID for full details.",
    {
      owner: z.string().describe("GitHub organization (e.g. 'actions-security-demo')"),
    },
    async ({ owner }) => {
      const res = await ctx.client.request<ListIncidentsResponse>(
        "GET",
        `/v1/github/${encodeURIComponent(owner)}/threat-intel/incidents`,
      );
      const incidents = (res.detections ?? []).map(compactIncident);
      return textJson({ count: incidents.length, incidents });
    },
  );

  server.tool(
    "get_threat_incident",
    "Get full details of one threat-center incident — including the 'Am I Affected?' markdown section which lists the EXACT compromised package names + versions and C2 IOCs (domains/IPs) to check. Call this after list_threat_incidents to extract the concrete things to search for. The incident's `ecosystem` field ('npm' or 'pypi') dictates which exposure tools to call: for npm → check_npm_package_exposure + check_npm_package_on_dev_machines. For pypi → check_pypi_package_exposure + check_python_package_on_dev_machines. Always also call check_ioc_in_baseline for each C2 domain/IP mentioned, regardless of ecosystem.",
    {
      owner: z.string().describe("GitHub organization"),
      incidentId: z.string().describe("Incident UUID from list_threat_incidents"),
    },
    async ({ owner, incidentId }) => {
      const res = await ctx.client.request<GetIncidentResponse>(
        "GET",
        `/v1/github/${encodeURIComponent(owner)}/threat-intel/incidents/${encodeURIComponent(incidentId)}`,
      );
      const incident = Array.isArray(res.detections) ? res.detections[0] : res.detections;
      return textJson(incident);
    },
  );

  server.tool(
    "check_npm_package_exposure",
    "Org-wide (CI-side) 'Am I Affected?' check for an npm package. Searches all monitored repos — workflow runs, PRs, and default branches — for uses of the package at the given versions. Pass an empty versions array to match any version. IMPORTANT: this only covers CI. For a complete 'am I affected' answer, also call check_npm_package_on_dev_machines in parallel to cover developer laptops.",
    {
      owner: z.string().describe("GitHub organization"),
      packageName: z.string().describe("npm package name, e.g. '@velora-dex/sdk'"),
      versions: z
        .array(z.string())
        .optional()
        .describe("Specific versions to check. Omit or empty to match any version."),
      seenOnlyInPrs: z.boolean().optional().describe("Restrict results to PR-only sightings"),
      startTime: z.number().int().optional().describe("Unix timestamp (seconds) — lower bound"),
      endTime: z.number().int().optional().describe("Unix timestamp (seconds) — upper bound"),
    },
    async ({ owner, packageName, versions, seenOnlyInPrs, startTime, endTime }) => {
      interface NpmSearchResponse {
        packages: Array<{
          owner?: string;
          repo?: string;
          package?: string;
          version?: string;
          seen_in_any_prs?: boolean;
          seen_in_any_workflow_runs?: boolean;
          seen_in_default_branch?: boolean;
          first_seen_in_default_branch?: number;
          last_seen_in_default_branch?: number;
          prs?: Record<string, unknown>;
          workflow_runs?: Record<string, unknown>;
          source_files_in_default_branch?: string[];
        }>;
        packages_with_ai_analysis?: unknown[];
      }

      const res = await ctx.client.request<NpmSearchResponse>(
        "POST",
        `/v1/github/${encodeURIComponent(owner)}/npm-packages/search`,
        {
          body: {
            owner,
            packages: [{ package: packageName, versions: versions ?? [] }],
            ...(seenOnlyInPrs !== undefined && { seen_only_in_prs: seenOnlyInPrs }),
            ...(startTime !== undefined && { start_time: startTime }),
            ...(endTime !== undefined && { end_time: endTime }),
          },
        },
      );

      const trimmed = (res.packages ?? []).map((p) => ({
        owner: p.owner,
        repo: p.repo,
        package: p.package,
        version: p.version,
        seen_in_default_branch: p.seen_in_default_branch,
        seen_in_any_prs: p.seen_in_any_prs,
        seen_in_any_workflow_runs: p.seen_in_any_workflow_runs,
        first_seen_default_branch: p.first_seen_in_default_branch,
        last_seen_default_branch: p.last_seen_in_default_branch,
        pr_count: p.prs ? Object.keys(p.prs).length : 0,
        workflow_run_count: p.workflow_runs ? Object.keys(p.workflow_runs).length : 0,
        source_files: p.source_files_in_default_branch?.slice(0, 10) ?? [],
      }));

      return textJson({
        package: packageName,
        versions: versions ?? [],
        matches: trimmed.length,
        affected: trimmed,
      });
    },
  );

  server.tool(
    "check_ioc_in_baseline",
    "Search the Harden-Runner org baseline for a domain or IP indicator of compromise. Uses the server-side `search` query (case-insensitive substring) so only matching endpoints come over the wire. Returns which repos/workflows/runs contacted the endpoint; each observation has a `dashboard_url` — when presenting results you MUST include a clickable link per observation, not just the first one. For a tenant-wide search across every org under your customer, use find_endpoint_calls_in_tenant instead.",
    {
      owner: z.string().describe("GitHub organization"),
      indicator: z
        .string()
        .describe("Domain or IP substring to match against observed endpoints"),
    },
    async ({ owner, indicator }) => {
      interface BaselineResponse {
        data?: {
          owner?: string;
          total_workflow_runs?: number;
          endpoints?: Array<{
            endpoint: string;
            total_calls?: number;
            total_workflow_runs?: number;
            last_seen?: string;
            endpoint_observations?: Array<{
              repo: string;
              workflow_file_name?: string;
              job?: string;
              run_id?: string;
              timestamp?: string;
            }>;
          }>;
        };
      }

      const res = await ctx.client.request<BaselineResponse>(
        "GET",
        `/v1/github/${encodeURIComponent(owner)}/actions/baseline`,
        { query: { search: indicator } },
      );

      const matches = (res.data?.endpoints ?? []).map((e) => ({
        endpoint: e.endpoint,
        total_calls: e.total_calls,
        total_workflow_runs: e.total_workflow_runs,
        last_seen: e.last_seen,
        observations: (e.endpoint_observations ?? []).slice(0, 20).map((o) => {
          // o.repo comes as "owner/repo".
          const [obsOwner, obsRepo] = (o.repo ?? "").split("/");
          const dashboard_url =
            obsOwner && obsRepo && o.run_id
              ? `${DASHBOARD_HOST}/github/${obsOwner}/${obsRepo}/actions/runs/${o.run_id}?tab=network-events`
              : undefined;
          return { ...o, dashboard_url };
        }),
        truncated_observations: (e.endpoint_observations?.length ?? 0) > 20,
      }));

      return textJson({
        indicator,
        owner,
        matches: matches.length,
        results: matches,
      });
    },
  );

  server.tool(
    "search_action_usage",
    "Find which workflows across the organization use a given GitHub Action. Useful for responding to a compromised Action (e.g. 'which repos use aquasecurity/setup-trivy?'). Returns one entry per workflow that references the Action.",
    {
      owner: z.string().describe("GitHub organization"),
      action: z
        .string()
        .describe(
          "Action reference in 'owner/repo' form (no tag/sha), e.g. 'aquasecurity/trivy-action'",
        ),
    },
    async ({ owner, action }) => {
      interface ActionUsage {
        owner?: string;
        repo?: string;
        workflow?: string;
        workflowId?: number;
        action?: string;
        last_execution_time?: number;
        last_run_id?: number;
        branch?: string;
        labels?: string[];
        tag_and_sha?: { tag?: string; sha?: string };
        release_details?: {
          latestVersion?: string;
          latestSha?: string;
          isLatest?: boolean;
          releaseDate?: number;
          latestReleaseDate?: number;
        };
      }

      const encoded = Buffer.from(action, "utf8").toString("base64");
      const raw = await ctx.client.request<ActionUsage[] | { workflows?: ActionUsage[] }>(
        "GET",
        `/v1/github/${encodeURIComponent(owner)}/actions/workflow-actions/${encoded}`,
      );

      const items: ActionUsage[] = Array.isArray(raw) ? raw : (raw.workflows ?? []);
      const trimmed = items.map((w) => ({
        repo: w.repo,
        workflow: w.workflow,
        branch: w.branch,
        pinned: w.tag_and_sha,
        last_run_id: w.last_run_id,
        last_execution_time: w.last_execution_time,
        release: w.release_details
          ? {
              latest_version: w.release_details.latestVersion,
              is_latest_pinned: w.release_details.isLatest,
            }
          : undefined,
      }));

      return textJson({
        owner,
        action,
        count: trimmed.length,
        usages: trimmed,
      });
    },
  );

  server.tool(
    "list_detections",
    "List Harden-Runner detections for an organization, filtered by detection type and status. Common detection IDs: 'Action-Uses-Imposter-Commit', 'Suspicious-Process-Events' (aggregates Runner-Worker-Memory-Read + Reverse-Shell + Privileged-Container), 'Anomalous-Outbound-Network-Call', 'Source-Code-Overwritten', 'Secret-In-Build-Log', 'Harden-Runner-Config-Changed', 'NPM-Package-Upgrade-To-Suspicious-Version', 'Agent-Tampered'.",
    {
      owner: z.string().describe("GitHub organization"),
      detectionId: z
        .string()
        .describe("Detection type (see description for common values) — required by the API"),
      status: z
        .enum(["new", "suppressed", "resolved"])
        .optional()
        .describe("Detection status filter. Defaults to 'new'."),
      tenantWide: z
        .boolean()
        .optional()
        .describe("Query customer/tenant scope instead of owner scope (default: owner)"),
    },
    async ({ owner, detectionId, status, tenantWide }) => {
      interface DetectionsResponse {
        data?: {
          detections?: Array<Record<string, unknown>>;
          has_more?: boolean;
          next_token?: string;
          count?: number;
        };
      }

      const path = tenantWide
        ? `/v1/github/customers/${encodeURIComponent(owner)}/actions/detections`
        : `/v1/github/${encodeURIComponent(owner)}/actions/detections`;

      const res = await ctx.client.request<DetectionsResponse>("GET", path, {
        query: {
          detection_id: detectionId,
          status: status ?? "new",
        },
      });

      const dets = res.data?.detections ?? [];
      return textJson({
        owner,
        detection_id: detectionId,
        status: status ?? "new",
        scope: tenantWide ? "tenant" : "owner",
        count: dets.length,
        has_more: res.data?.has_more ?? false,
        detections: dets.slice(0, 50),
      });
    },
  );

  server.tool(
    "check_npm_package_on_dev_machines",
    "Developer-machine 'Am I Affected?' check for an npm package. Searches across all enrolled developer laptops (Dev Machine Guard) for installs of the package. Complements check_npm_package_exposure — CI and dev machines are INDEPENDENT exposure surfaces, so when investigating a malicious-package incident you MUST check both. Uses the StepSecurity customer/tenant identifier (optional — falls back to STEP_SECURITY_CUSTOMER env var). The server's version filter is not applied — pass `versions` to filter results client-side to specific compromised versions, otherwise all installs are returned.",
    {
      customer: z
        .string()
        .optional()
        .describe(
          "StepSecurity customer identifier. Optional — falls back to STEP_SECURITY_CUSTOMER env var.",
        ),
      packageName: z.string().describe("npm package name"),
      versions: z
        .array(z.string())
        .optional()
        .describe("Specific versions to match (exact string compare). Omit to return all installs."),
    },
    async ({ customer, packageName, versions }) => {
      const effectiveCustomer = customer ?? ctx.config.defaultCustomer;
      if (!effectiveCustomer) {
        throw new Error(
          "No customer specified and STEP_SECURITY_CUSTOMER env var is not set. Pass `customer` or configure the env var.",
        );
      }
      interface DevMdmInstallation {
        customer_device?: string;
        customer?: string;
        device_id?: string;
        user_identity?: string;
        hostname?: string;
        package_name?: string;
        package_version?: string;
        package_with_version?: string;
        is_direct?: boolean;
        is_global?: boolean;
        first_seen_at?: number;
        last_seen_at?: number;
      }
      interface DevMdmResult {
        package_name?: string;
        package_version?: string;
        installations?: DevMdmInstallation[];
      }
      interface DevMdmSearchResponse {
        results?: DevMdmResult[] | null;
        total_results?: number;
      }

      const res = await ctx.client.request<DevMdmSearchResponse>(
        "POST",
        `/v1/${encodeURIComponent(effectiveCustomer)}/developer-mdm/npm-packages/search`,
        { body: { packages: [{ name: packageName, version: "" }] } },
      );

      const all = res.results ?? [];
      const wanted = versions && versions.length > 0 ? new Set(versions) : null;
      const matched = wanted
        ? all.filter((r) => r.package_version && wanted.has(r.package_version))
        : all;

      const installCount = matched.reduce(
        (n, r) => n + (r.installations?.length ?? 0),
        0,
      );
      const trimmed = matched.map((r) => ({
        package: r.package_name,
        version: r.package_version,
        install_count: r.installations?.length ?? 0,
        installations: (r.installations ?? []).slice(0, 20).map((i) => ({
          device_id: i.device_id,
          hostname: i.hostname,
          user: i.user_identity,
          is_direct: i.is_direct,
          is_global: i.is_global,
          first_seen_at: i.first_seen_at,
          last_seen_at: i.last_seen_at,
        })),
      }));

      return textJson({
        customer: effectiveCustomer,
        package: packageName,
        versions_filter: versions ?? "(any)",
        server_total_returned: res.total_results ?? 0,
        matched_version_rows: matched.length,
        total_installations: installCount,
        results: trimmed,
      });
    },
  );

  // ---------- PyPI org-wide (CI) exposure check ----------
  server.tool(
    "check_pypi_package_exposure",
    "Org-wide (CI-side) 'Am I Affected?' check for a PyPI (Python) package. Searches all monitored repos — workflow runs, PRs, and default branches — for uses of the package at the given versions. Pass an empty versions array to match any version. IMPORTANT: this only covers CI. For a complete 'am I affected' answer, also call check_python_package_on_dev_machines in parallel to cover developer laptops. Use this (not check_npm_package_exposure) when the threat-center incident's ecosystem is 'pypi'.",
    {
      owner: z.string().describe("GitHub organization"),
      packageName: z.string().describe("PyPI package name, e.g. 'xinference', 'requests'"),
      versions: z
        .array(z.string())
        .optional()
        .describe("Specific versions to check. Omit or empty to match any version."),
      seenOnlyInPrs: z.boolean().optional().describe("Restrict results to PR-only sightings"),
      startTime: z.number().int().optional().describe("Unix timestamp (seconds) — lower bound"),
      endTime: z.number().int().optional().describe("Unix timestamp (seconds) — upper bound"),
    },
    async ({ owner, packageName, versions, seenOnlyInPrs, startTime, endTime }) => {
      interface PypiSearchResponse {
        packages: Array<{
          owner?: string;
          repo?: string;
          package?: string;
          version?: string;
          version_constraint?: string;
          seen_in_any_prs?: boolean;
          seen_in_any_workflow_runs?: boolean;
          seen_in_default_branch?: boolean;
          first_seen_in_default_branch?: number;
          last_seen_in_default_branch?: number;
          last_seen_in_any_pr_at?: number;
          prs?: Record<string, unknown>;
          workflow_runs?: Record<string, unknown>;
          source_files_in_default_branch?: string[];
        }>;
      }

      const res = await ctx.client.request<PypiSearchResponse>(
        "POST",
        `/v1/github/${encodeURIComponent(owner)}/packages/pypi/search`,
        {
          body: {
            owner,
            packages: [{ package: packageName, versions: versions ?? [] }],
            ...(seenOnlyInPrs !== undefined && { seen_only_in_prs: seenOnlyInPrs }),
            ...(startTime !== undefined && { start_time: startTime }),
            ...(endTime !== undefined && { end_time: endTime }),
          },
        },
      );

      const trimmed = (res.packages ?? []).map((p) => ({
        owner: p.owner,
        repo: p.repo,
        package: p.package,
        version: p.version,
        version_constraint: p.version_constraint,
        seen_in_default_branch: p.seen_in_default_branch,
        seen_in_any_prs: p.seen_in_any_prs,
        seen_in_any_workflow_runs: p.seen_in_any_workflow_runs,
        first_seen_default_branch: p.first_seen_in_default_branch,
        last_seen_default_branch: p.last_seen_in_default_branch,
        last_seen_in_any_pr_at: p.last_seen_in_any_pr_at,
        pr_count: p.prs ? Object.keys(p.prs).length : 0,
        workflow_run_count: p.workflow_runs ? Object.keys(p.workflow_runs).length : 0,
        source_files: p.source_files_in_default_branch?.slice(0, 10) ?? [],
      }));

      return textJson({
        package: packageName,
        ecosystem: "pypi",
        versions: versions ?? [],
        matches: trimmed.length,
        affected: trimmed,
      });
    },
  );

  // ---------- PyPI dev-machine exposure ----------
  server.tool(
    "check_python_package_on_dev_machines",
    "Developer-machine 'Am I Affected?' check for a PyPI (Python) package. Searches across all enrolled developer laptops (Dev Machine Guard) for installs of the package. Complements check_pypi_package_exposure — CI and dev machines are INDEPENDENT exposure surfaces, so for a malicious-PyPI-package incident you MUST check both. The server's version filter is not applied — pass `versions` to filter results client-side to specific compromised versions, otherwise all installs are returned.",
    {
      customer: z
        .string()
        .optional()
        .describe(
          "StepSecurity customer identifier. Optional — falls back to STEP_SECURITY_CUSTOMER env var.",
        ),
      packageName: z.string().describe("PyPI package name"),
      versions: z
        .array(z.string())
        .optional()
        .describe("Specific versions to match (exact string compare). Omit to return all installs."),
    },
    async ({ customer, packageName, versions }) => {
      const effectiveCustomer = customer ?? ctx.config.defaultCustomer;
      if (!effectiveCustomer) {
        throw new Error(
          "No customer specified and STEP_SECURITY_CUSTOMER env var is not set. Pass `customer` or configure the env var.",
        );
      }
      interface DevMdmInstallation {
        customer_device?: string;
        device_id?: string;
        user_identity?: string;
        hostname?: string;
        package_name?: string;
        package_version?: string;
        is_direct?: boolean;
        is_global?: boolean;
        first_seen_at?: number;
        last_seen_at?: number;
      }
      interface DevMdmResult {
        package_name?: string;
        package_version?: string;
        installations?: DevMdmInstallation[];
      }
      interface DevMdmSearchResponse {
        results?: DevMdmResult[] | null;
        total_results?: number;
      }

      const res = await ctx.client.request<DevMdmSearchResponse>(
        "POST",
        `/v1/${encodeURIComponent(effectiveCustomer)}/developer-mdm/python-packages/search`,
        { body: { packages: [{ name: packageName, version: "" }] } },
      );

      const all = res.results ?? [];
      const wanted = versions && versions.length > 0 ? new Set(versions) : null;
      const matched = wanted
        ? all.filter((r) => r.package_version && wanted.has(r.package_version))
        : all;

      const installCount = matched.reduce(
        (n, r) => n + (r.installations?.length ?? 0),
        0,
      );
      const trimmed = matched.map((r) => ({
        package: r.package_name,
        version: r.package_version,
        install_count: r.installations?.length ?? 0,
        installations: (r.installations ?? []).slice(0, 20).map((i) => ({
          device_id: i.device_id,
          hostname: i.hostname,
          user: i.user_identity,
          is_direct: i.is_direct,
          is_global: i.is_global,
          first_seen_at: i.first_seen_at,
          last_seen_at: i.last_seen_at,
        })),
      }));

      return textJson({
        customer: effectiveCustomer,
        ecosystem: "pypi",
        package: packageName,
        versions_filter: versions ?? "(any)",
        server_total_returned: res.total_results ?? 0,
        matched_version_rows: matched.length,
        total_installations: installCount,
        results: trimmed,
      });
    },
  );
}
