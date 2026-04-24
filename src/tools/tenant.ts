import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolContext } from "./index.js";
import { DASHBOARD_HOST } from "../config.js";

export function registerTenantTools(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "get_my_tenant",
    "Return the StepSecurity customer/tenant identifier configured on this MCP server, along with a link to the tenant's admin console. Call this when the user asks 'what's my tenant?', 'which customer am I scoped to?', or wants to confirm the default before a detection sweep. Reads the STEP_SECURITY_CUSTOMER env var set in the MCP client config.",
    {},
    async () => {
      const c = ctx.config.defaultCustomer;
      if (!c) {
        return {
          content: [
            {
              type: "text",
              text:
                "No default tenant is configured. Set STEP_SECURITY_CUSTOMER in the MCP server's env (in your .mcp.json or claude_desktop_config.json) to avoid passing `customer` on every tool call. You can also pass the customer explicitly as a tool argument.",
            },
          ],
        };
      }
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                tenant: c,
                admin_console_url: `${DASHBOARD_HOST}/${c}/admin-console`,
                note: "This is the default used when a tool's 'customer' argument is omitted. Callers can override by passing a different customer explicitly.",
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );
}
