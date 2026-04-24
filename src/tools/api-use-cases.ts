import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolContext } from "./index.js";
import { DASHBOARD_HOST } from "../config.js";

// Tools backed by the step-security/api-use-cases scenarios.
// Some fan out per repo and may take tens of seconds on large orgs.

function textJson(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

// Small p-limit replacement — runs `tasks` with at most `concurrency` in flight.
async function pMap<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i] as T, i);
    }
  });
  await Promise.all(workers);
  return results;
}

export function registerApiUseCaseTools(server: McpServer, ctx: ToolContext): void {
  // ---------- List GitHub orgs under a tenant ----------
  interface TenantOrg {
    owner?: string;
    organization?: string;
    customer?: string;
    server?: string;
  }

  server.tool(
    "list_tenant_github_orgs",
    "List every GitHub organization installed under a StepSecurity tenant. Call this first when a user asks for a tenant-wide view (e.g. 'find repos across my tenant using bun.sh') — then fan out find_repos_using_endpoint or similar per-org tools across the result. Each org has a `dashboard_url` pointing to its security summary — surface it as a clickable link per org. `customer` is optional; falls back to STEP_SECURITY_CUSTOMER.",
    {
      customer: z
        .string()
        .optional()
        .describe(
          "StepSecurity customer/tenant identifier. Optional — falls back to STEP_SECURITY_CUSTOMER env var.",
        ),
    },
    async ({ customer }) => {
      const effective = customer ?? ctx.config.defaultCustomer;
      if (!effective) {
        throw new Error(
          "No customer specified and STEP_SECURITY_CUSTOMER env var is not set. Pass `customer` or configure the env var.",
        );
      }
      const res = await ctx.client.request<TenantOrg[]>(
        "GET",
        `/v1/${encodeURIComponent(effective)}/github/organizations`,
      );
      const orgs = (res ?? []).map((o) => {
        const org = o.organization ?? o.owner;
        return {
          org,
          server: o.server || undefined,
          dashboard_url: org
            ? `${DASHBOARD_HOST}/github/${org}/actions/security-summary`
            : undefined,
        };
      });
      return textJson({
        tenant: effective,
        org_count: orgs.length,
        orgs,
      });
    },
  );

  // ---------- List recent workflow runs (discovery for get-run-detail tools) ----------
  interface WorkflowRunSummary {
    id?: string;
    name?: string;
    repo?: string;
    head_branch?: string;
    conclusion?: string;
    event?: string;
    run_number?: number;
    start_time_utc?: string;
    title?: string;
    action_count?: number;
    job_count?: number;
    execution_duration_in_seconds?: number;
    path?: string;
  }
  interface RunsListResponse {
    total_workflow_runs?: number;
    workflow_runs?: WorkflowRunSummary[];
    current_page?: number;
    total_pages?: number;
  }

  server.tool(
    "list_recent_workflow_runs",
    "List the 100 most recent Harden-Runner-monitored workflow runs for a GitHub organization, optionally narrowed to one repository. Use this to discover run IDs when the user asks about a run without giving an explicit ID — e.g. 'the latest run of trivy-scan in poc-1'. Every result has a `dashboard_url` — when you present runs to the user you MUST include a clickable link per run, not just the first one.",
    {
      owner: z.string().describe("GitHub organization"),
      repo: z
        .string()
        .optional()
        .describe("Repository name (without owner). Omit for org-wide runs."),
      page: z.number().int().min(1).optional().describe("Page number (default 1)"),
    },
    async ({ owner, repo, page }) => {
      const path = repo
        ? `/v1/github/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs`
        : `/v1/github/${encodeURIComponent(owner)}/actions/runs`;
      const res = await ctx.client.request<RunsListResponse>("GET", path, {
        query: page ? { page } : undefined,
      });
      const runs = (res.workflow_runs ?? []).map((r) => {
        // r.repo is "owner/repo"; fall back to arg if missing.
        const [repoOwner, repoName] = (r.repo ?? `${owner}/${repo ?? ""}`).split("/");
        const dashboard_url =
          repoOwner && repoName && r.id
            ? `${DASHBOARD_HOST}/github/${repoOwner}/${repoName}/actions/runs/${r.id}`
            : undefined;
        return {
          run_id: r.id,
          workflow: r.name,
          repo: r.repo,
          branch: r.head_branch,
          event: r.event,
          conclusion: r.conclusion,
          run_number: r.run_number,
          started_at: r.start_time_utc,
          duration_seconds: r.execution_duration_in_seconds,
          job_count: r.job_count,
          dashboard_url,
        };
      });
      return textJson({
        owner,
        repo: repo ?? "(all repos)",
        total_workflow_runs: res.total_workflow_runs ?? runs.length,
        current_page: res.current_page ?? page ?? 1,
        total_pages: res.total_pages,
        count: runs.length,
        runs,
      });
    },
  );

  // ---------- Scenario 3: GitHub API calls made during a workflow run ----------
  interface RunDetail {
    name?: string;
    jobs?: Array<{
      id?: number | string;
      name?: string;
      steps?: Array<{
        name?: string;
        number?: number;
        tools?: Array<{
          name?: string;
          https_endpoints?: Array<{
            method?: string;
            host?: string;
            path?: string;
            timestamp?: string;
          }>;
        }>;
      }>;
    }>;
  }

  server.tool(
    "list_github_api_calls_in_run",
    "List every HTTPS call to github.com or api.github.com made by jobs in a specific workflow run. Useful for auditing which GitHub API endpoints a workflow touches — detecting writes to unexpected repos, surprising org access, or API calls from third-party Actions. Fast: one upstream API call. Requires a run_id — if the user doesn't supply one, call list_recent_workflow_runs first to find it. Returns calls grouped by job with step/tool attribution. The response has a top-level `dashboard_url` for the run AND a per-job `dashboard_url` deep-linking to the network-events tab scoped to that job. When presenting results, include the per-job link next to each job header.",
    {
      owner: z.string().describe("GitHub organization"),
      repo: z.string().describe("Repository name (without owner)"),
      runId: z.union([z.string(), z.number()]).describe("Workflow run ID"),
    },
    async ({ owner, repo, runId }) => {
      const res = await ctx.client.request<RunDetail>(
        "GET",
        `/v1/github/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/actions/runs/${encodeURIComponent(String(runId))}`,
      );

      const jobs = (res.jobs ?? []).map((job) => {
        const calls: Array<Record<string, unknown>> = [];
        for (const step of job.steps ?? []) {
          for (const tool of step.tools ?? []) {
            for (const ep of tool.https_endpoints ?? []) {
              if (ep.host !== "api.github.com" && ep.host !== "github.com") continue;
              calls.push({
                step: step.name,
                step_number: step.number,
                tool: tool.name,
                method: ep.method,
                host: ep.host,
                path: ep.path,
                timestamp: ep.timestamp,
              });
            }
          }
        }
        const jobDashboardUrl = job.id
          ? `${DASHBOARD_HOST}/github/${owner}/${repo}/actions/runs/${runId}?jobId=${job.id}&tab=network-events`
          : undefined;
        return {
          job_id: job.id,
          job: job.name,
          call_count: calls.length,
          dashboard_url: jobDashboardUrl,
          calls,
        };
      });

      const totalCalls = jobs.reduce((n, j) => n + j.call_count, 0);
      return textJson({
        workflow: res.name,
        owner,
        repo,
        run_id: runId,
        total_github_api_calls: totalCalls,
        dashboard_url: `${DASHBOARD_HOST}/github/${owner}/${repo}/actions/runs/${runId}`,
        jobs,
      });
    },
  );

  // ---------- Tenant-wide search: find every job observation of an endpoint ----------
  interface TenantBaselineResponse {
    data?: {
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

  server.tool(
    "find_endpoint_calls_in_tenant",
    "Find every workflow-run observation of a given network endpoint across EVERY GitHub org installed under the tenant. Takes an endpoint substring (domain or IP), lists the tenant's orgs, and fans out a baseline search per org with bounded concurrency. Returns a flat list of observations: {org, repo, workflow, job, run_id, timestamp, dashboard_url}. Use this instead of check_ioc_in_baseline when the user asks 'did anyone in our tenant contact X?'. When presenting results you MUST include a clickable dashboard_url per observation.",
    {
      customer: z
        .string()
        .optional()
        .describe(
          "StepSecurity customer/tenant identifier. Optional — falls back to STEP_SECURITY_CUSTOMER env var.",
        ),
      endpoint: z
        .string()
        .describe(
          "Endpoint substring to match against observed endpoints, e.g. 'registry.npmjs.org', '8.8.8.8'",
        ),
      concurrency: z
        .number()
        .int()
        .min(1)
        .max(20)
        .optional()
        .describe("Max parallel org requests (default: 5)"),
      observationsPerOrg: z
        .number()
        .int()
        .min(1)
        .max(500)
        .optional()
        .describe("Cap on observations returned per matching org endpoint (default: 50)"),
    },
    async ({ customer, endpoint, concurrency, observationsPerOrg }) => {
      const effective = customer ?? ctx.config.defaultCustomer;
      if (!effective) {
        throw new Error(
          "No customer specified and STEP_SECURITY_CUSTOMER env var is not set. Pass `customer` or configure the env var.",
        );
      }

      const orgList = await ctx.client.request<TenantOrg[]>(
        "GET",
        `/v1/${encodeURIComponent(effective)}/github/organizations`,
      );
      const orgs = (orgList ?? [])
        .map((o) => o.organization ?? o.owner)
        .filter((o): o is string => !!o);

      const capPerOrg = observationsPerOrg ?? 50;
      const perOrg = await pMap(orgs, concurrency ?? 5, async (org) => {
        try {
          const res = await ctx.client.request<TenantBaselineResponse>(
            "GET",
            `/v1/github/${encodeURIComponent(org)}/actions/baseline`,
            { query: { search: endpoint } },
          );
          const observations: Array<Record<string, unknown>> = [];
          for (const ep of res.data?.endpoints ?? []) {
            for (const o of (ep.endpoint_observations ?? []).slice(0, capPerOrg)) {
              const [obsOwner, obsRepo] = (o.repo ?? "").split("/");
              observations.push({
                org,
                endpoint: ep.endpoint,
                repo: obsRepo ?? o.repo,
                workflow: o.workflow_file_name,
                job: o.job,
                run_id: o.run_id,
                timestamp: o.timestamp,
                dashboard_url:
                  obsOwner && obsRepo && o.run_id
                    ? `${DASHBOARD_HOST}/github/${obsOwner}/${obsRepo}/actions/runs/${o.run_id}?tab=network-events`
                    : undefined,
              });
            }
          }
          return observations;
        } catch (err) {
          ctx.logger.warn("tenant baseline fetch failed for org", {
            org,
            error: err instanceof Error ? err.message : String(err),
          });
          return [];
        }
      });

      const all = perOrg.flat();
      const orgsWithMatches = new Set(
        all.map((o) => o.org).filter((v): v is string => typeof v === "string"),
      );

      return textJson({
        tenant: effective,
        endpoint,
        orgs_scanned: orgs.length,
        orgs_with_matches: orgsWithMatches.size,
        total_observations: all.length,
        observations_per_org_cap: capPerOrg,
        observations: all,
      });
    },
  );

  // ---------- Scenario 1: find repos in an org whose baseline contains an endpoint ----------
  interface SecuritySummaryRow {
    Owner?: string;
    Repo?: string;
  }
  interface BaselineResponse {
    // The repo-level baseline endpoint returns an envelope similar to the org one.
    data?: { endpoints?: Array<{ endpoint: string }> };
    endpoints?: Array<{ endpoint: string }>;
  }

  server.tool(
    "find_repos_using_endpoint",
    "Find every repo in an org whose Harden-Runner baseline contains a given network endpoint (domain or IP, substring match). Useful for questions like 'which repos contact bun.sh?', 'who still uses registry.npmjs.org?', or migration planning. Fans out one request per repo with bounded concurrency — expect 10–60 seconds on orgs with many repos. Returns only repos that matched — each one has a `baseline_url` which you MUST surface as a clickable link per repo (not just the first one). NOTE: this tool is single-org. For a tenant-wide sweep, first call list_tenant_github_orgs and then call this per org.",
    {
      owner: z.string().describe("GitHub organization"),
      endpoint: z
        .string()
        .describe(
          "Endpoint substring to search for, e.g. 'bun.sh:443', 'registry.npmjs.org', '8.8.8.8'",
        ),
      concurrency: z
        .number()
        .int()
        .min(1)
        .max(50)
        .optional()
        .describe("Max parallel requests (default: 10)"),
    },
    async ({ owner, endpoint, concurrency }) => {
      // 1. Get repo list from the security-summary endpoint.
      const summary = await ctx.client.request<SecuritySummaryRow[]>(
        "GET",
        `/v1/github/${encodeURIComponent(owner)}/actions/security-summary`,
      );
      const repos = (summary ?? [])
        .map((r) => r.Repo)
        .filter((r): r is string => !!r && r !== "#all#");

      ctx.logger.debug("scanning repos for endpoint", {
        owner,
        endpoint,
        repoCount: repos.length,
        concurrency: concurrency ?? 10,
      });

      // 2. Fan out one baseline?search=endpoint call per repo.
      const results = await pMap(repos, concurrency ?? 10, async (repo) => {
        try {
          const res = await ctx.client.request<BaselineResponse>(
            "GET",
            `/v1/github/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/baseline`,
            { query: { search: endpoint } },
          );
          const endpoints = res.data?.endpoints ?? res.endpoints ?? [];
          if (endpoints.length === 0) return null;
          return {
            repo,
            matched_endpoints: endpoints.map((e) => e.endpoint),
            baseline_url: `${DASHBOARD_HOST}/github/${owner}/actions/baseline?tab=repositories&repository=${encodeURIComponent(repo)}`,
          };
        } catch (err) {
          ctx.logger.warn("baseline fetch failed for repo", {
            owner,
            repo,
            error: err instanceof Error ? err.message : String(err),
          });
          return null;
        }
      });

      const matched = results.filter(
        (r): r is NonNullable<typeof r> => r !== null,
      );

      return textJson({
        owner,
        endpoint,
        repos_scanned: repos.length,
        repos_matched: matched.length,
        matches: matched,
      });
    },
  );
}
