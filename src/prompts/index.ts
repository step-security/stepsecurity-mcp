import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerPrompts(server: McpServer): void {
  server.prompt(
    "am-i-affected",
    "Full 'am I affected?' investigation for a supply-chain incident in a given org.",
    {
      org: z.string().describe("GitHub organization (e.g. 'actions-security-demo')"),
      incident: z
        .string()
        .describe(
          "Free-text incident reference: package name, CVE, or short description (e.g. 'axios', 'trivy compromise', 'CVE-2024-1234')",
        ),
    },
    ({ org, incident }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Investigate whether ${org} is affected by this supply-chain incident: "${incident}".

Do this strictly using the StepSecurity MCP tools, in this order:

1. Call list_threat_incidents for ${org} and find the incident that best matches "${incident}".
2. Call get_threat_incident on the matching incident id and read the 'Am I Affected?' section to extract:
   - the exact compromised package(s) and version(s)
   - any IOC domains or IP addresses
   - any compromised GitHub Actions
3. In parallel, for each compromised package — pick the tool pair matching the incident's ecosystem:
   - ecosystem='npm':  check_npm_package_exposure + check_npm_package_on_dev_machines
   - ecosystem='pypi': check_pypi_package_exposure + check_python_package_on_dev_machines
4. In parallel, for each IOC:
   - Call check_ioc_in_baseline
5. If a GitHub Action is compromised:
   - Call search_action_usage for each affected action
   - Call list_detections with detection_id='Action-Uses-Imposter-Commit'
   - Call list_detections with detection_id='Suspicious-Process-Events'

Then summarise findings as a punch list of concrete exposures (repo/workflow/run, dev machine hostname/user, baseline endpoint observations). If nothing matches, say so clearly.`,
          },
        },
      ],
    }),
  );
}
