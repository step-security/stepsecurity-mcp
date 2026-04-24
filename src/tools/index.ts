import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { StepSecurityClient } from "../client.js";
import type { Logger } from "../logger.js";
import type { Config } from "../config.js";
import { registerPingTool } from "./ping.js";
import { registerDescribeTool } from "./describe.js";
import { registerThreatCenterTools } from "./threat-center.js";
import { registerDetectionTools } from "./detections.js";
import { registerTenantTools } from "./tenant.js";
import { registerApiUseCaseTools } from "./api-use-cases.js";
import { registerSuppressionTools } from "./suppression.js";

export interface ToolContext {
  client: StepSecurityClient;
  logger: Logger;
  config: Config;
}

export function registerTools(server: McpServer, ctx: ToolContext): void {
  registerDescribeTool(server, ctx);
  registerPingTool(server, ctx);
  registerTenantTools(server, ctx);
  registerThreatCenterTools(server, ctx);
  registerDetectionTools(server, ctx);
  registerApiUseCaseTools(server, ctx);
  registerSuppressionTools(server, ctx);
}
