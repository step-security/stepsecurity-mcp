import type { Config } from "./config.js";
import { API_HOST } from "./config.js";
import type { Logger } from "./logger.js";

export interface ApiError extends Error {
  status: number;
  body: string;
}

export class StepSecurityClient {
  constructor(
    private readonly config: Config,
    private readonly logger: Logger,
  ) {}

  async request<T>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    options: { query?: Record<string, string | number | boolean | undefined>; body?: unknown } = {},
  ): Promise<T> {
    const url = new URL(API_HOST + path);
    if (options.query) {
      for (const [k, v] of Object.entries(options.query)) {
        if (v !== undefined) url.searchParams.set(k, String(v));
      }
    }

    const started = Date.now();
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": "stepsecurity-mcp/0.1.0",
      },
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    });

    const durationMs = Date.now() - started;
    this.logger.debug("upstream request", {
      method,
      path,
      status: res.status,
      durationMs,
    });

    const text = await res.text();
    if (!res.ok) {
      const err = new Error(
        `StepSecurity API ${method} ${path} returned ${res.status}`,
      ) as ApiError;
      err.status = res.status;
      err.body = text;
      throw err;
    }

    if (!text) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      return text as unknown as T;
    }
  }
}
