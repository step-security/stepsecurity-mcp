import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolContext } from "./index.js";
import { DASHBOARD_HOST } from "../config.js";

// A tenant in StepSecurity is a customer (a set of GitHub orgs where the app
// is installed). All detection tools default to the tenant/customer scope —
// calls hit /v1/github/customers/:customer/actions/detections and aggregate
// detections from every org under that customer.
//
// `customer` is optional on every tool: if omitted, the server falls back to
// the STEP_SECURITY_CUSTOMER env var so the user doesn't have to retype their
// tenant on every prompt.

interface DetectionsEnvelope<T> {
  data?: {
    detections?: T[];
    has_more?: boolean;
    next_token?: string;
    count?: number;
  };
}

const StatusEnum = z.enum(["new", "suppressed", "resolved"]);

const commonArgs = {
  customer: z
    .string()
    .optional()
    .describe(
      "StepSecurity customer/tenant identifier. Optional — if omitted, falls back to STEP_SECURITY_CUSTOMER env var. Returns detections aggregated across ALL GitHub orgs installed under this tenant.",
    ),
  status: StatusEnum.optional().describe("Detection status filter. Defaults to 'new'."),
  limit: z
    .number()
    .int()
    .min(1)
    .max(200)
    .optional()
    .describe("Max detections to return (1-200). Defaults to 50."),
  orgScope: z
    .string()
    .optional()
    .describe(
      "Optional: restrict to a single GitHub org under this tenant (uses the owner-scoped endpoint instead of tenant-wide).",
    ),
} as const;

interface ToolProcess {
  name?: string;
  sha256?: string;
  parent?: ToolProcess | null;
}

interface BaseDetection {
  id?: string;
  owner?: string;
  repo?: string;
  run_id?: string;
  run_attempt?: string | number;
  job?: string;
  job_id?: string;
  job_name?: string;
  workflow_path?: string;
  workflow_id?: string | number;
  timestamp?: string;
  // The server returns `tool` as a nested object {name, sha256, parent}
  // — not a flat string. The `process` suppression condition matches against `tool.name`.
  tool?: ToolProcess;
  direct_ip_address?: string;
  is_resolved?: boolean;
  is_suppressed?: boolean;
}

export function extractProcess(d: BaseDetection): string | undefined {
  const name = d.tool?.name;
  return name && name.trim() !== "" ? name : undefined;
}

function textJson(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function buildDashboardUrl(
  d: BaseDetection,
  tab: string,
  statusFilter?: string,
): string | undefined {
  if (!d.owner || !d.repo || !d.run_id) return undefined;
  const base = `${DASHBOARD_HOST}/github/${d.owner}/${d.repo}/actions/runs/${d.run_id}`;
  const params = new URLSearchParams();
  if (d.job_id) params.set("jobId", String(d.job_id));
  params.set("tab", tab);
  if (statusFilter) params.set("status", statusFilter);
  return `${base}?${params.toString()}`;
}

function compactBase(d: BaseDetection, dashboardUrl: string | undefined) {
  return {
    id: d.id,
    owner: d.owner,
    repo: d.repo,
    workflow: d.workflow_path,
    run_id: d.run_id,
    run_attempt: d.run_attempt,
    job: d.job ?? d.job_name,
    timestamp: d.timestamp,
    process: extractProcess(d),
    resolved: d.is_resolved,
    suppressed: d.is_suppressed,
    dashboard_url: dashboardUrl,
  };
}

function resolveCustomer(ctx: ToolContext, customer: string | undefined): string {
  const effective = customer ?? ctx.config.defaultCustomer;
  if (!effective) {
    throw new Error(
      "No customer specified and STEP_SECURITY_CUSTOMER env var is not set. Pass the `customer` argument or configure the env var.",
    );
  }
  return effective;
}

function resolveScopePath(customer: string, orgScope: string | undefined): string {
  if (orgScope) {
    return `/v1/github/${encodeURIComponent(orgScope)}/actions/detections`;
  }
  return `/v1/github/customers/${encodeURIComponent(customer)}/actions/detections`;
}

async function fetchDetections<T extends BaseDetection>(
  ctx: ToolContext,
  args: {
    customer: string | undefined;
    detectionId: string;
    status?: z.infer<typeof StatusEnum>;
    limit?: number;
    orgScope?: string;
  },
): Promise<{ envelope: DetectionsEnvelope<T>; customer: string }> {
  const customer = resolveCustomer(ctx, args.customer);
  const envelope = await ctx.client.request<DetectionsEnvelope<T>>(
    "GET",
    resolveScopePath(customer, args.orgScope),
    {
      query: {
        detection_id: args.detectionId,
        status: args.status ?? "new",
        limit: args.limit,
      },
    },
  );
  return { envelope, customer };
}

export function registerDetectionTools(server: McpServer, ctx: ToolContext): void {
  // ---------- Anomalous (new) outbound network calls ----------
  interface NewOutboundDetection extends BaseDetection {
    endpoint?: string;
    expected_outbound_connections?: string[];
  }

  server.tool(
    "list_anomalous_network_calls",
    "List anomalous outbound network-call detections across the tenant (all orgs installed under the customer). 'Anomalous' = a destination endpoint was contacted that is NOT in the repo's Harden-Runner baseline of allowed endpoints — a common indicator of supply-chain exfiltration. Typically the most-used detection type during an investigation. Every result has a `dashboard_url` — when you present detections to the user you MUST include a clickable link per detection, not just the first one.",
    commonArgs,
    async (args) => {
      const { envelope, customer } = await fetchDetections<NewOutboundDetection>(ctx, {
        ...args,
        detectionId: "New-Outbound-Network-Call",
      });
      const dets = (envelope.data?.detections ?? []).map((d) => ({
        ...compactBase(d, buildDashboardUrl(d, "network-events", "anomalous")),
        endpoint: d.endpoint,
        direct_ip: d.direct_ip_address,
        expected: d.expected_outbound_connections ?? [],
      }));
      return textJson({
        scope: args.orgScope ? `org:${args.orgScope}` : `tenant:${customer}`,
        status: args.status ?? "new",
        count: dets.length,
        has_more: envelope.data?.has_more ?? false,
        detections: dets,
      });
    },
  );

  // ---------- Blocked domain calls ----------
  interface DomainBlockedDetection extends BaseDetection {
    endpoint?: string;
  }

  server.tool(
    "list_blocked_domain_calls",
    "List detections where Harden-Runner actively BLOCKED an outbound network call (egress-policy enforcement). Different from anomalous calls: blocked = the call was prevented; anomalous = the call happened but wasn't in baseline. Every result has a `dashboard_url` — when you present detections to the user you MUST include a clickable link per detection, not just the first one.",
    commonArgs,
    async (args) => {
      const { envelope, customer } = await fetchDetections<DomainBlockedDetection>(ctx, {
        ...args,
        detectionId: "Domain-Blocked",
      });
      const dets = (envelope.data?.detections ?? []).map((d) => ({
        ...compactBase(d, buildDashboardUrl(d, "network-events", "blocked")),
        endpoint: d.endpoint,
        direct_ip: d.direct_ip_address,
      }));
      return textJson({
        scope: args.orgScope ? `org:${args.orgScope}` : `tenant:${customer}`,
        status: args.status ?? "new",
        count: dets.length,
        has_more: envelope.data?.has_more ?? false,
        detections: dets,
      });
    },
  );

  // ---------- HTTPS outbound calls ----------
  interface HttpsCallDetection extends BaseDetection {
    host?: string;
    method?: string;
    path?: string;
  }

  server.tool(
    "list_https_outbound_calls",
    "List HTTPS outbound network-call detections (TLS-intercepted calls with method + path). Useful when you need to see WHAT an outbound call did — e.g. POSTs to a suspicious endpoint during a build. Every result has a `dashboard_url` — when you present detections to the user you MUST include a clickable link per detection, not just the first one.",
    commonArgs,
    async (args) => {
      const { envelope, customer } = await fetchDetections<HttpsCallDetection>(ctx, {
        ...args,
        detectionId: "HTTPS-Outbound-Network-Call",
      });
      const dets = (envelope.data?.detections ?? []).map((d) => ({
        ...compactBase(d, buildDashboardUrl(d, "network-events", "anomalous")),
        host: d.host,
        method: d.method,
        path: d.path,
      }));
      return textJson({
        scope: args.orgScope ? `org:${args.orgScope}` : `tenant:${customer}`,
        status: args.status ?? "new",
        count: dets.length,
        has_more: envelope.data?.has_more ?? false,
        detections: dets,
      });
    },
  );

  // ---------- Suspicious process events (virtual aggregate) ----------
  interface SuspiciousProcessDetection extends BaseDetection {
    process_events?: unknown;
  }

  server.tool(
    "list_suspicious_process_events",
    "List suspicious-process-event detections across the tenant. This is a virtual detection ID that aggregates three real types: Runner-Worker-Memory-Read (credential theft from runner memory), Reverse-Shell, and Privileged-Container. Use for runtime-evidence of compromise during an incident. Every result has a `dashboard_url` — when you present detections to the user you MUST include a clickable link per detection, not just the first one.",
    commonArgs,
    async (args) => {
      const { envelope, customer } = await fetchDetections<SuspiciousProcessDetection>(ctx, {
        ...args,
        detectionId: "Suspicious-Process-Events",
      });
      const dets = (envelope.data?.detections ?? []).map((d) => ({
        ...compactBase(d, buildDashboardUrl(d,"process-events")),
        process_events: d.process_events,
      }));
      return textJson({
        scope: args.orgScope ? `org:${args.orgScope}` : `tenant:${customer}`,
        status: args.status ?? "new",
        count: dets.length,
        has_more: envelope.data?.has_more ?? false,
        detections: dets,
      });
    },
  );

  // ---------- Secrets in build log ----------
  interface SecretInBuildLogDetection extends BaseDetection {
    secret?: string;
    rule_id?: string;
    line_number?: number;
    step_number?: number;
  }

  server.tool(
    "list_secrets_in_build_log",
    "List detections where a secret (API key, private key, token, etc.) was detected in a CI build log. The API returns the secret already masked (e.g. '----****') — safe to display. Includes rule_id (which detector fired), line_number and step_number for navigation to the leak. Every result has a `dashboard_url` — when you present detections to the user you MUST include a clickable link per detection, not just the first one.",
    commonArgs,
    async (args) => {
      const { envelope, customer } = await fetchDetections<SecretInBuildLogDetection>(ctx, {
        ...args,
        detectionId: "Secret-In-Build-Log",
      });
      const dets = (envelope.data?.detections ?? []).map((d) => ({
        ...compactBase(d, buildDashboardUrl(d,"controls")),
        rule_id: d.rule_id,
        masked_secret: d.secret,
        line_number: d.line_number,
        step_number: d.step_number,
      }));
      return textJson({
        scope: args.orgScope ? `org:${args.orgScope}` : `tenant:${customer}`,
        status: args.status ?? "new",
        count: dets.length,
        has_more: envelope.data?.has_more ?? false,
        detections: dets,
      });
    },
  );

  // ---------- Imposter-commit detections ----------
  interface ImposterCommitDetection extends BaseDetection {
    action?: string;
    sha?: string;
    tag?: string;
  }

  server.tool(
    "list_imposter_commit_detections",
    "List detections where a GitHub Action is pinned to a commit SHA that doesn't match any legitimate tag or branch head of that action's repo — a strong indicator of Action-tampering (e.g. a compromised tag pointing to malicious commit). Every result has a `dashboard_url` — when you present detections to the user you MUST include a clickable link per detection, not just the first one.",
    commonArgs,
    async (args) => {
      const { envelope, customer } = await fetchDetections<ImposterCommitDetection>(ctx, {
        ...args,
        detectionId: "Action-Uses-Imposter-Commit",
      });
      const dets = (envelope.data?.detections ?? []).map((d) => ({
        ...compactBase(d, buildDashboardUrl(d,"process-events")),
        action: d.action,
        sha: d.sha,
        tag: d.tag,
      }));
      return textJson({
        scope: args.orgScope ? `org:${args.orgScope}` : `tenant:${customer}`,
        status: args.status ?? "new",
        count: dets.length,
        has_more: envelope.data?.has_more ?? false,
        detections: dets,
      });
    },
  );
}
