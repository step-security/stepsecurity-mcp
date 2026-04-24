import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolContext } from "./index.js";

// Placeholder tool so the server has something to list before real tools land.
// Replace/remove once real tools are registered.
export function registerPingTool(server: McpServer, _ctx: ToolContext): void {
  server.tool(
    "ping",
    "Returns 'pong' — use to verify the MCP server is reachable.",
    { message: z.string().optional().describe("Optional echo payload") },
    async ({ message }) => ({
      content: [
        { type: "text", text: message ? `pong: ${message}` : "pong" },
      ],
    }),
  );
}
