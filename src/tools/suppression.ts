import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolContext } from "./index.js";
import { DASHBOARD_HOST } from "../config.js";

// Suppression-rule tools. Write tools require confirm: true and are expected
// to be called AFTER preview_suppression_rule has shown the user the impact.
//
// Creating a rule retroactively suppresses matching past detections on the
// server side (synchronous — see agent-api detection_rules.go:suppressOldDetections).

interface RuleConditions {
  owner?: string;
  repo?: string;
  workflow?: string;
  job?: string;
  endpoint?: string;
  ip_address?: string;
  process?: string;
  host?: string;
  file?: string;
  file_path?: string;
  secret_type?: string;
  action?: string;
  [k: string]: string | undefined;
}

interface SeverityAction {
  type: "ignore" | "set-severity";
  new_severity?: string;
}

interface SuppressionRule {
  rule_id?: string;
  id?: string;
  name?: string;
  description?: string;
  customer?: string;
  conditions?: RuleConditions;
  severity_action?: SeverityAction;
  created_by?: string;
  created_on?: string;
  updated_by?: string;
  updated_on?: string;
}

const ScopeConditionKeys = ["owner", "repo", "workflow", "job"] as const;

function textJson(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function resolveCustomer(ctx: ToolContext, customer: string | undefined): string {
  const effective = customer ?? ctx.config.defaultCustomer;
  if (!effective) {
    throw new Error(
      "No customer specified and STEP_SECURITY_CUSTOMER env var is not set. Pass `customer` or configure the env var.",
    );
  }
  return effective;
}

function normalizeConditions(raw: RuleConditions): RuleConditions {
  // API convention: owner/repo/workflow/job are always present, with "*" for
  // unspecified scope levels. Fill them in so callers don't have to.
  const out: RuleConditions = { ...raw };
  for (const k of ScopeConditionKeys) {
    if (out[k] === undefined || out[k] === "") out[k] = "*";
  }
  return out;
}

// Approximate client-side matcher. Server has a richer matcher (regex, CIDR)
// but exact + "*" covers the typical anomalous-network-call case. Flagged as
// "approximate" in the preview response so the user knows to verify post-create.
function matchesCondition(
  detectionValue: string | undefined,
  pattern: string,
): boolean {
  if (pattern === "*") return true;
  if (!detectionValue) return false;
  return detectionValue === pattern;
}

function detectionFieldForKey(
  d: Record<string, unknown>,
  key: string,
): string | undefined {
  // The `process` condition matches against Tool.Name. The server returns
  // `tool` as a nested object: {name, sha256, parent}. Pull name out.
  if (key === "process") {
    const t = d["tool"];
    if (t && typeof t === "object") {
      const name = (t as { name?: unknown }).name;
      if (typeof name === "string" && name.trim() !== "") {
        // Strip any path so matches with basename work (e.g. "/usr/bin/curl" → "curl").
        const last = name.split("/").pop();
        return last || name;
      }
    }
    return undefined;
  }

  // ip_address: match against direct_ip_address first, fall back to endpoint
  // if endpoint is formatted as "<ip>:<port>" (server does the same).
  if (key === "ip_address") {
    const dip = d["direct_ip_address"];
    if (typeof dip === "string" && dip.trim() !== "") {
      const endpoint = d["endpoint"];
      if (
        typeof endpoint === "string" &&
        endpoint.startsWith(dip + ":")
      ) {
        return endpoint;
      }
      return dip;
    }
    return undefined;
  }

  const aliases: Record<string, string[]> = {
    owner: ["owner"],
    repo: ["repo"],
    workflow: ["workflow_path", "workflow"],
    job: ["job", "job_name"],
    endpoint: ["endpoint"],
    host: ["host"],
    file: ["file"],
    file_path: ["path", "file_path"],
    secret_type: ["rule_id", "secret_type"],
    action: ["action"],
  };
  for (const field of aliases[key] ?? [key]) {
    const v = d[field];
    if (typeof v === "string" && v) return v;
  }
  return undefined;
}

function buildDetectionDashboardUrl(
  d: Record<string, unknown>,
  tab: string,
): string | undefined {
  const owner = typeof d.owner === "string" ? d.owner : undefined;
  const repo = typeof d.repo === "string" ? d.repo : undefined;
  const runId = typeof d.run_id === "string" ? d.run_id : undefined;
  if (!owner || !repo || !runId) return undefined;
  const params = new URLSearchParams();
  if (typeof d.job_id === "string" || typeof d.job_id === "number")
    params.set("jobId", String(d.job_id));
  params.set("tab", tab);
  return `${DASHBOARD_HOST}/github/${owner}/${repo}/actions/runs/${runId}?${params.toString()}`;
}

function dashboardTabForDetectionId(detectionId: string): string {
  if (
    detectionId === "New-Outbound-Network-Call" ||
    detectionId === "Domain-Blocked" ||
    detectionId === "HTTPS-Outbound-Network-Call" ||
    detectionId === "Suspicious-Network-Call"
  )
    return "network-events";
  if (detectionId === "Secret-In-Build-Log" || detectionId === "Secret-In-Artifact")
    return "controls";
  if (detectionId === "Source-Code-Overwritten") return "file-events";
  return "process-events";
}

interface DetectionsEnvelope {
  data?: {
    detections?: Array<Record<string, unknown>>;
    has_more?: boolean;
    next_token?: string;
  };
}

async function fetchDetectionsForMatching(
  ctx: ToolContext,
  customer: string,
  detectionId: string,
  status: "new" | "suppressed",
  limit = 200,
): Promise<Array<Record<string, unknown>>> {
  const res = await ctx.client.request<DetectionsEnvelope>(
    "GET",
    `/v1/github/customers/${encodeURIComponent(customer)}/actions/detections`,
    { query: { detection_id: detectionId, status, limit } },
  );
  return res.data?.detections ?? [];
}

const customerArg = z
  .string()
  .optional()
  .describe(
    "StepSecurity customer/tenant identifier. Optional — falls back to STEP_SECURITY_CUSTOMER env var.",
  );

const confirmArg = z
  .boolean()
  .describe(
    "Set to true to actually execute the write. Any other value (including omitted) returns an error — this is a safety check so the LLM cannot write without explicit user approval.",
  );

// Endpoints that are commonly abused by attackers for payload delivery,
// exfiltration, or C2 — suppressing detections pointing to these is almost
// always a mistake, even when the calling process looks benign. The LLM must
// refuse to propose or create a rule that silences these, and must warn the
// user when a broader rule (e.g. process-only) would incidentally silence
// them too. Host match is substring so both 'gist.github.com' and
// 'gist.github.com:443' hit.
const HIGH_RISK_ENDPOINT_SUBSTRINGS: string[] = [
  "gist.github.com",
  "gist.githubusercontent.com",
];

function isHighRiskEndpoint(endpoint: string | undefined): boolean {
  if (!endpoint) return false;
  const lower = endpoint.toLowerCase();
  return HIGH_RISK_ENDPOINT_SUBSTRINGS.some((s) => lower.includes(s));
}

function extractProcessName(d: Record<string, unknown>): string | undefined {
  const t = d["tool"];
  if (t && typeof t === "object") {
    const name = (t as { name?: unknown }).name;
    if (typeof name === "string" && name.trim() !== "")
      return name.split("/").pop() || name;
  }
  return undefined;
}

// VPN / mesh-networking daemons that legitimately connect to many distinct
// peer IPs and coordination endpoints as part of normal operation. A single
// process-scoped rule usually suppresses all of their benign anomalies
// (both domain-based and direct-IP-based) without needing per-destination
// rules. This is a hint to the LLM, not a hard-coded suppression.
//
// Other daemons (dockerd, containerd, snapd, kubelet, systemd-resolved, etc.)
// are deliberately NOT on this list — they can make security-relevant calls
// and deserve per-destination review.
const VPN_PROCESS_HINTS: string[] = [
  "tailscaled",
  "tailscale",
  "twingate",
  "twingate-connector",
  "twingate-client",
  "zerotier-one",
  "zerotier",
  "netbird",
  "cloudflared",
  "warp-svc",
  "openvpn",
  "wireguard",
  "wg-quick",
];

interface NetworkDetection {
  owner?: string;
  repo?: string;
  workflow_path?: string;
  job?: string;
  job_id?: string;
  run_id?: string;
  timestamp?: string;
  endpoint?: string;
  direct_ip_address?: string;
  tool?: { name?: string; parent?: unknown } | null;
}

function processNameFromDetection(d: NetworkDetection): string {
  const raw = d.tool?.name ?? "";
  if (!raw) return "(unknown)";
  return raw.split("/").pop() || raw;
}

export function registerSuppressionTools(server: McpServer, ctx: ToolContext): void {
  // ---------- analyze by process ----------
  server.tool(
    "analyze_anomalous_calls_by_process",
    "Group tenant-wide anomalous network-call detections by the calling process. Goal: spot VPN / mesh-networking daemons (tailscaled, twingate, zerotier-one, netbird, cloudflared, warp-svc, openvpn, wireguard) that are legitimately fanning out to many peer IPs and coordination endpoints as normal operation. For those, a single process-scoped rule suppresses both domain AND direct-IP benign anomalies with one rule. Returns per-process: count, distinct endpoints, distinct direct IPs, sample detections (with dashboard links), and a suggested single suppression rule. When a VPN process appears (is_vpn_process_candidate=true), propose a process-wide rule (just {process: <name>, owner: '*', ...}). Do NOT auto-propose process-wide rules for other processes (dockerd, containerd, snapd, curl, etc.) — those can make security-relevant calls and deserve per-destination review.",
    {
      customer: customerArg,
      minCount: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(
          "Hide processes with fewer than this many anomalies (default: 2).",
        ),
    },
    async ({ customer, minCount }) => {
      const c = resolveCustomer(ctx, customer);
      const envelope = await ctx.client.request<{
        data?: { detections?: NetworkDetection[] };
      }>(
        "GET",
        `/v1/github/customers/${encodeURIComponent(c)}/actions/detections`,
        {
          query: {
            detection_id: "New-Outbound-Network-Call",
            status: "new",
            limit: 200,
          },
        },
      );
      const dets = envelope.data?.detections ?? [];

      const grouped = new Map<
        string,
        {
          count: number;
          endpoints: Set<string>;
          ips: Set<string>;
          samples: Array<{
            owner?: string;
            repo?: string;
            workflow?: string;
            run_id?: string;
            endpoint?: string;
            direct_ip?: string;
            dashboard_url?: string;
          }>;
        }
      >();

      for (const d of dets) {
        const name = processNameFromDetection(d);
        const bucket =
          grouped.get(name) ??
          (grouped
            .set(name, {
              count: 0,
              endpoints: new Set<string>(),
              ips: new Set<string>(),
              samples: [],
            })
            .get(name) as NonNullable<ReturnType<typeof grouped.get>>);
        bucket.count += 1;
        if (d.endpoint) bucket.endpoints.add(d.endpoint);
        if (d.direct_ip_address) bucket.ips.add(d.direct_ip_address);
        if (bucket.samples.length < 5) {
          const url =
            d.owner && d.repo && d.run_id
              ? `${DASHBOARD_HOST}/github/${d.owner}/${d.repo}/actions/runs/${d.run_id}?${
                  d.job_id ? `jobId=${d.job_id}&` : ""
                }tab=network-events&status=anomalous`
              : undefined;
          bucket.samples.push({
            owner: d.owner,
            repo: d.repo,
            workflow: d.workflow_path,
            run_id: d.run_id,
            endpoint: d.endpoint,
            direct_ip: d.direct_ip_address,
            dashboard_url: url,
          });
        }
      }

      const min = minCount ?? 2;
      const groups = Array.from(grouped.entries())
        .filter(([, v]) => v.count >= min)
        .sort((a, b) => b[1].count - a[1].count)
        .map(([process, v]) => {
          const isVpnProcess =
            process !== "(unknown)" &&
            VPN_PROCESS_HINTS.some(
              (p) => p.toLowerCase() === process.toLowerCase(),
            );
          const riskyDestinations = Array.from(v.endpoints).filter((e) =>
            isHighRiskEndpoint(e),
          );
          const riskySamples = v.samples
            .filter((s) => isHighRiskEndpoint(s.endpoint))
            .slice(0, 5);
          return {
            process,
            count: v.count,
            distinct_endpoints: v.endpoints.size,
            distinct_direct_ips: v.ips.size,
            is_vpn_process_candidate: isVpnProcess,
            endpoints_sample: Array.from(v.endpoints).slice(0, 10),
            direct_ips_sample: Array.from(v.ips).slice(0, 10),
            // If this process has touched attacker-staging endpoints, a process-
            // wide rule would silence those too. LLM must surface this to the
            // user and refuse to auto-propose such a rule.
            risky_destinations_suppressed_by_process_rule:
              riskyDestinations.length > 0 ? riskyDestinations : undefined,
            risky_destination_samples:
              riskySamples.length > 0 ? riskySamples : undefined,
            suggested_rule: {
              detection_id: "New-Outbound-Network-Call",
              conditions: {
                process,
                owner: "*",
                repo: "*",
                workflow: "*",
                job: "*",
              },
              severity_action: { type: "ignore" },
              rationale: isVpnProcess
                ? "VPN / mesh-networking daemon — legitimately contacts many peer IPs and control endpoints. A single process-scoped rule covers both domain and direct-IP anomalies without needing per-destination rules (absent conditions are wildcards server-side)."
                : "Groups all anomalous calls attributed to this process. Per-destination review recommended — a process-wide rule could over-suppress real issues.",
              blocked_reason:
                riskyDestinations.length > 0
                  ? `This process's anomalies include attacker-staging endpoints (${riskyDestinations.join(", ")}). DO NOT propose this process-wide rule — it would silence those detections too. Instead, propose narrower rules that exclude the risky destinations, or reject the scenario and ask the user to review the risky detections manually.`
                  : undefined,
            },
            sample_detections: v.samples,
          };
        });

      return textJson({
        tenant: c,
        detection_id: "New-Outbound-Network-Call",
        total_anomalies_scanned: dets.length,
        processes_returned: groups.length,
        min_count_filter: min,
        note: "For any process you want to suppress, call preview_suppression_rule with the `suggested_rule.conditions` to see exact impact before create.",
        processes: groups,
      });
    },
  );

  // ---------- list ----------
  server.tool(
    "list_suppression_rules",
    "List all suppression (detection) rules configured for the tenant. Use this before creating a new rule to check for duplicates or near-overlaps. Read-only.",
    { customer: customerArg },
    async ({ customer }) => {
      const c = resolveCustomer(ctx, customer);
      const rules = await ctx.client.request<SuppressionRule[]>(
        "GET",
        `/v1/${encodeURIComponent(c)}/detection-rules`,
      );
      return textJson({
        tenant: c,
        count: (rules ?? []).length,
        rules: (rules ?? []).map((r) => ({
          rule_id: r.rule_id,
          detection_id: r.id,
          name: r.name,
          description: r.description,
          conditions: r.conditions,
          severity_action: r.severity_action,
          created_by: r.created_by,
          created_on: r.created_on,
        })),
      });
    },
  );

  // ---------- get ----------
  server.tool(
    "get_suppression_rule",
    "Get one suppression rule by id. Read-only.",
    { customer: customerArg, ruleId: z.string().describe("Rule id (UUID)") },
    async ({ customer, ruleId }) => {
      const c = resolveCustomer(ctx, customer);
      const rule = await ctx.client.request<SuppressionRule>(
        "GET",
        `/v1/${encodeURIComponent(c)}/detection-rules/${encodeURIComponent(ruleId)}`,
      );
      return textJson(rule);
    },
  );

  // ---------- preview ----------
  server.tool(
    "preview_suppression_rule",
    "APPROXIMATE client-side preview of what creating a suppression rule would do. Fetches recent detections of the given detection_id and filters them against the proposed conditions, returning the count and up to 20 samples (with dashboard_url per sample). Use this BEFORE create_suppression_rule to show the user concrete impact. Preview uses exact + wildcard matching — the server's matcher is stricter (CIDR for ip_address, regex), so the final count after create may differ slightly.",
    {
      customer: customerArg,
      detectionId: z
        .string()
        .describe(
          "Detection type the rule targets, e.g. 'New-Outbound-Network-Call', 'Secret-In-Build-Log', 'Action-Uses-Imposter-Commit'",
        ),
      conditions: z
        .record(z.string(), z.string())
        .describe(
          "Match conditions. Keys: owner, repo, workflow, job (omit or '*' for wildcard), plus type-specific keys like endpoint, ip_address, process, host, file, file_path, secret_type, action.",
        ),
    },
    async ({ customer, detectionId, conditions }) => {
      const c = resolveCustomer(ctx, customer);
      const normalized = normalizeConditions(conditions);

      // Sample both 'new' and 'suppressed' so the user sees total reach.
      const [open, already] = await Promise.all([
        fetchDetectionsForMatching(ctx, c, detectionId, "new", 200),
        fetchDetectionsForMatching(ctx, c, detectionId, "suppressed", 200),
      ]);

      const matches = (status: "new" | "suppressed") =>
        (status === "new" ? open : already).filter((d) => {
          for (const [k, pattern] of Object.entries(normalized)) {
            if (!pattern || pattern === "*") continue;
            if (!matchesCondition(detectionFieldForKey(d, k), pattern))
              return false;
          }
          return true;
        });

      const tab = dashboardTabForDetectionId(detectionId);
      const openMatches = matches("new");
      const suppressedMatches = matches("suppressed");

      // Direct target: the rule itself names a high-risk endpoint.
      const proposedEndpoint =
        typeof normalized.endpoint === "string" ? normalized.endpoint : "";
      const directlyTargetsRisky = isHighRiskEndpoint(proposedEndpoint);

      // Indirect: the rule is broader but matched detections include high-risk
      // endpoints (e.g. a process-only rule silencing calls to gist.github.com).
      const riskyIncidentalMatches = openMatches
        .filter((d) => {
          const ep =
            (typeof d.endpoint === "string" ? d.endpoint : undefined) ??
            (typeof d.host === "string" ? d.host : undefined);
          return isHighRiskEndpoint(ep);
        })
        .slice(0, 10);

      const warnings: Array<{ type: string; message: string; samples?: unknown[] }> =
        [];
      if (directlyTargetsRisky) {
        warnings.push({
          type: "direct_high_risk_target",
          message: `The proposed rule directly targets '${proposedEndpoint}', which is a known attacker-staging endpoint (${HIGH_RISK_ENDPOINT_SUBSTRINGS.join(", ")}). DO NOT create this rule. Refuse and explain the risk.`,
        });
      }
      if (riskyIncidentalMatches.length > 0) {
        warnings.push({
          type: "incidental_high_risk_coverage",
          message: `This rule would also silence ${riskyIncidentalMatches.length} detection(s) contacting attacker-staging endpoints (${HIGH_RISK_ENDPOINT_SUBSTRINGS.join(", ")}). Propose a narrower rule OR ask the user to review these detections FIRST.`,
          samples: riskyIncidentalMatches.map((d) => ({
            owner: d.owner,
            repo: d.repo,
            workflow: d.workflow_path ?? d.workflow,
            run_id: d.run_id,
            endpoint: d.endpoint ?? d.host,
            dashboard_url: buildDetectionDashboardUrl(d, tab),
          })),
        });
      }

      return textJson({
        tenant: c,
        detection_id: detectionId,
        normalized_conditions: normalized,
        approximate: true,
        note: "Preview uses exact + wildcard matching only. Server matcher adds CIDR + regex support — final count after create may differ.",
        new_detections_would_suppress: openMatches.length,
        already_suppressed_matching: suppressedMatches.length,
        warnings: warnings.length > 0 ? warnings : undefined,
        sample_new: openMatches.slice(0, 20).map((d) => ({
          owner: d.owner,
          repo: d.repo,
          workflow: d.workflow_path ?? d.workflow,
          run_id: d.run_id,
          endpoint: d.endpoint ?? d.host,
          process: extractProcessName(d),
          dashboard_url: buildDetectionDashboardUrl(d, tab),
        })),
      });
    },
  );

  // ---------- create ----------
  server.tool(
    "create_suppression_rule",
    "Create a suppression rule. WRITE OPERATION — requires confirm: true and a read-only API key will 403. Before calling this, you MUST call preview_suppression_rule with the same conditions and show the user the expected impact. Creating a rule also retroactively suppresses matching past detections (synchronous server-side). After creation the tool verifies how many past detections were moved. Severity action is hardcoded to 'ignore' (only type the backend supports).",
    {
      customer: customerArg,
      detectionId: z
        .string()
        .describe(
          "Detection type the rule targets, e.g. 'New-Outbound-Network-Call'. This becomes the rule's `id` field.",
        ),
      name: z.string().describe("Short human-readable rule name"),
      description: z.string().optional().describe("Longer rationale for the rule"),
      conditions: z
        .record(z.string(), z.string())
        .describe(
          "Match conditions. owner/repo/workflow/job are auto-filled with '*' if omitted. Include type-specific keys (endpoint, ip_address, process, host, file, file_path, secret_type, action) as needed.",
        ),
      confirm: confirmArg,
    },
    async ({ customer, detectionId, name, description, conditions, confirm }) => {
      if (confirm !== true) {
        throw new Error(
          "create_suppression_rule requires confirm: true. Call preview_suppression_rule first and only set confirm: true after the user explicitly approves.",
        );
      }
      const c = resolveCustomer(ctx, customer);
      const normalized = normalizeConditions(conditions);

      // Hard block: refuse rules that directly target high-risk endpoints
      // even with confirm: true. The risk is too high to be gated only by
      // LLM-level instructions.
      const ep =
        typeof normalized.endpoint === "string" ? normalized.endpoint : "";
      const host = typeof normalized.host === "string" ? normalized.host : "";
      if (isHighRiskEndpoint(ep) || isHighRiskEndpoint(host)) {
        throw new Error(
          `Refusing to create a suppression rule that directly targets a high-risk endpoint (${HIGH_RISK_ENDPOINT_SUBSTRINGS.join(", ")}). These are commonly abused for payload delivery, exfiltration, and C2. If you believe the detection is a genuine false positive, review the specific run(s) first and suppress narrower signals instead.`,
        );
      }

      const body = {
        id: detectionId,
        name,
        description: description ?? "",
        conditions: normalized,
        severity_action: { type: "ignore" as const },
      };

      let created: SuppressionRule;
      try {
        created = await ctx.client.request<SuppressionRule>(
          "POST",
          `/v1/${encodeURIComponent(c)}/detection-rules`,
          { body },
        );
      } catch (err: unknown) {
        const e = err as { status?: number; message?: string };
        if (e.status === 403) {
          throw new Error(
            "Write denied (403): the configured STEP_SECURITY_API_KEY does not have write permission for this scope. Swap to an admin key, or narrow the rule scope — tenant-wide rules (owner='*') require tenant admin; org rules require admin on the named org.",
          );
        }
        throw err;
      }

      // Verify retroactive suppression by pulling suppressed detections of
      // this type and counting those attributed to the new rule. The server
      // runs the back-fill synchronously before returning, so no wait needed.
      let retroCount = 0;
      try {
        const suppressed = await fetchDetectionsForMatching(
          ctx,
          c,
          detectionId,
          "suppressed",
          200,
        );
        retroCount = suppressed.filter(
          (d) => d.suppress_rule_id === created.rule_id,
        ).length;
      } catch {
        // Verification failure is non-fatal.
      }

      return textJson({
        rule: created,
        retroactive_suppression: {
          past_detections_moved_to_suppressed: retroCount,
          note: "Server applies the rule to all past detections synchronously on create. Partial write failures are logged server-side but not returned; re-run list_detections if you need an exhaustive count.",
        },
      });
    },
  );

  // ---------- update ----------
  server.tool(
    "update_suppression_rule",
    "Update an existing suppression rule (name, description, or conditions). WRITE OPERATION — requires confirm: true.",
    {
      customer: customerArg,
      ruleId: z.string().describe("Rule id to update"),
      name: z.string().optional(),
      description: z.string().optional(),
      conditions: z.record(z.string(), z.string()).optional(),
      confirm: confirmArg,
    },
    async ({ customer, ruleId, name, description, conditions, confirm }) => {
      if (confirm !== true) {
        throw new Error(
          "update_suppression_rule requires confirm: true. Explain the change to the user first and only set confirm: true after approval.",
        );
      }
      const c = resolveCustomer(ctx, customer);

      // Fetch current so we send a complete object on PUT.
      const current = await ctx.client.request<SuppressionRule>(
        "GET",
        `/v1/${encodeURIComponent(c)}/detection-rules/${encodeURIComponent(ruleId)}`,
      );
      const body = {
        ...current,
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
        ...(conditions !== undefined && {
          conditions: normalizeConditions(conditions),
        }),
      };

      try {
        const updated = await ctx.client.request<SuppressionRule>(
          "PUT",
          `/v1/${encodeURIComponent(c)}/detection-rules/${encodeURIComponent(ruleId)}`,
          { body },
        );
        return textJson({ rule: updated });
      } catch (err: unknown) {
        const e = err as { status?: number };
        if (e.status === 403) {
          throw new Error(
            "Write denied (403): your API key lacks write permission for this rule.",
          );
        }
        throw err;
      }
    },
  );

  // ---------- delete ----------
  server.tool(
    "delete_suppression_rule",
    "Delete a suppression rule. WRITE OPERATION — requires confirm: true. NOTE: deleting a rule does NOT un-suppress detections it previously matched; they remain in the suppressed state with the deleted rule_id attached.",
    {
      customer: customerArg,
      ruleId: z.string().describe("Rule id to delete"),
      confirm: confirmArg,
    },
    async ({ customer, ruleId, confirm }) => {
      if (confirm !== true) {
        throw new Error(
          "delete_suppression_rule requires confirm: true. Confirm the rule id with the user before calling.",
        );
      }
      const c = resolveCustomer(ctx, customer);
      try {
        await ctx.client.request<unknown>(
          "DELETE",
          `/v1/${encodeURIComponent(c)}/detection-rules/${encodeURIComponent(ruleId)}`,
        );
        return textJson({
          deleted: true,
          rule_id: ruleId,
          note: "Past detections suppressed by this rule remain suppressed. To unsuppress them, change status via the detections API or in the dashboard.",
        });
      } catch (err: unknown) {
        const e = err as { status?: number };
        if (e.status === 403) {
          throw new Error("Write denied (403): your API key lacks write permission.");
        }
        throw err;
      }
    },
  );
}
