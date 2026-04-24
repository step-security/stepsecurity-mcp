// All logs must go to stderr. The MCP stdio transport uses stdout for
// JSON-RPC frames — any stray write to stdout corrupts the protocol.

type Level = "debug" | "info" | "warn" | "error";
const order: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export function createLogger(minLevel: Level) {
  const min = order[minLevel];
  const emit = (level: Level, msg: string, fields?: Record<string, unknown>) => {
    if (order[level] < min) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      msg,
      ...fields,
    });
    process.stderr.write(line + "\n");
  };
  return {
    debug: (msg: string, fields?: Record<string, unknown>) => emit("debug", msg, fields),
    info: (msg: string, fields?: Record<string, unknown>) => emit("info", msg, fields),
    warn: (msg: string, fields?: Record<string, unknown>) => emit("warn", msg, fields),
    error: (msg: string, fields?: Record<string, unknown>) => emit("error", msg, fields),
  };
}

export type Logger = ReturnType<typeof createLogger>;
