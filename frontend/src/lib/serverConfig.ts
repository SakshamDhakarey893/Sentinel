export interface ServerConfig {
  apiUrl: string;
  wsUrl: string;
  source: "runtime" | "env" | "default";
}

const RUNTIME_SERVER_CONFIG_KEY = "sentinel_server_config";
const DEFAULT_API_BASE = "http://localhost:8080";
const DEFAULT_WS_URL = "ws://localhost:8080/ws";

/**
 * Derives a WebSocket URL (ws:// or wss://) from an HTTP/HTTPS API URL.
 */
export function deriveWsUrl(apiUrl: string): string {
  const clean = apiUrl.trim().replace(/\/+$/, "");
  if (clean.startsWith("https://")) {
    return clean.replace(/^https:\/\//, "wss://") + "/ws";
  }
  if (clean.startsWith("http://")) {
    return clean.replace(/^http:\/\//, "ws://") + "/ws";
  }
  if (clean.startsWith("wss://") || clean.startsWith("ws://")) {
    return clean.endsWith("/ws") ? clean : `${clean}/ws`;
  }
  // Default fallback if protocol is missing
  return `ws://${clean}/ws`;
}

/**
 * Validates and normalizes an HTTP/HTTPS or WS URL.
 */
export function normalizeApiUrl(input: string): string {
  let url = input.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(url) && !/^wss?:\/\//i.test(url)) {
    // If user typed 'relay.example.com', default to https (or http for localhost/ips)
    if (url.startsWith("localhost") || url.startsWith("127.0.0.1")) {
      url = `http://${url}`;
    } else {
      url = `https://${url}`;
    }
  }
  return url;
}

/**
 * Returns the currently active Sentinel Relay Server configuration.
 * Priority:
 * 1. Runtime override stored in localStorage (`sentinel_server_config`)
 * 2. Environment variables (`NEXT_PUBLIC_SENTINEL_API_URL` or `NEXT_PUBLIC_API_URL`)
 * 3. Default fallback (`http://localhost:8080`)
 */
export function getActiveServerConfig(): ServerConfig {
  // 1. Check runtime localStorage override
  if (typeof window !== "undefined") {
    try {
      const stored = localStorage.getItem(RUNTIME_SERVER_CONFIG_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.apiUrl) {
          const apiUrl = parsed.apiUrl.trim().replace(/\/+$/, "");
          const wsUrl = parsed.wsUrl || deriveWsUrl(apiUrl);
          return {
            apiUrl,
            wsUrl,
            source: "runtime",
          };
        }
      }
    } catch {}
  }

  // 2. Check environment variables
  const envApi =
    process.env.NEXT_PUBLIC_SENTINEL_API_URL ||
    process.env.NEXT_PUBLIC_API_URL;
  const envWs =
    process.env.NEXT_PUBLIC_SENTINEL_WS_URL ||
    process.env.NEXT_PUBLIC_WS_URL;

  if (envApi && envApi.trim()) {
    const apiUrl = envApi.trim().replace(/\/+$/, "");
    const wsUrl = envWs && envWs.trim() ? envWs.trim() : deriveWsUrl(apiUrl);
    return {
      apiUrl,
      wsUrl,
      source: "env",
    };
  }

  // 3. Fallback to default
  return {
    apiUrl: DEFAULT_API_BASE,
    wsUrl: DEFAULT_WS_URL,
    source: "default",
  };
}

/**
 * Saves a new runtime server configuration override in localStorage.
 */
export function saveRuntimeServerConfig(
  inputApiUrl: string,
  inputWsUrl?: string,
): { success: boolean; apiUrl: string; wsUrl: string; error?: string } {
  if (typeof window === "undefined") {
    return {
      success: false,
      apiUrl: DEFAULT_API_BASE,
      wsUrl: DEFAULT_WS_URL,
      error: "Window not available",
    };
  }

  try {
    const normalizedApi = normalizeApiUrl(inputApiUrl);
    // Basic URL validation
    new URL(normalizedApi);

    const normalizedWs = inputWsUrl
      ? inputWsUrl.trim()
      : deriveWsUrl(normalizedApi);

    localStorage.setItem(
      RUNTIME_SERVER_CONFIG_KEY,
      JSON.stringify({ apiUrl: normalizedApi, wsUrl: normalizedWs }),
    );

    return {
      success: true,
      apiUrl: normalizedApi,
      wsUrl: normalizedWs,
    };
  } catch (err: any) {
    return {
      success: false,
      apiUrl: DEFAULT_API_BASE,
      wsUrl: DEFAULT_WS_URL,
      error: `Invalid URL format: ${err?.message || String(err)}`,
    };
  }
}

/**
 * Clears the runtime server override, returning configuration to env or defaults.
 */
export function clearRuntimeServerConfig(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(RUNTIME_SERVER_CONFIG_KEY);
}
