export const API_HOST = "https://agent.api.stepsecurity.io";
export const DASHBOARD_HOST = "https://app.stepsecurity.io";

export interface Config {
  apiKey: string;
  defaultCustomer?: string;
  logLevel: "debug" | "info" | "warn" | "error";
}

export function loadConfig(): Config {
  const apiKey = process.env.STEP_SECURITY_API_KEY;
  if (!apiKey) {
    throw new Error(
      "STEP_SECURITY_API_KEY is required. Set it in the MCP client config or environment.",
    );
  }

  const defaultCustomer = process.env.STEP_SECURITY_CUSTOMER?.trim() || undefined;

  const rawLevel = (process.env.LOG_LEVEL ?? "info").toLowerCase();
  const logLevel: Config["logLevel"] =
    rawLevel === "debug" || rawLevel === "warn" || rawLevel === "error"
      ? rawLevel
      : "info";

  return { apiKey, defaultCustomer, logLevel };
}
