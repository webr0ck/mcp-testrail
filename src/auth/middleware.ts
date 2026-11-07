import type { IncomingMessage, ServerResponse } from "node:http";
import type { TokenClaims, TokenStore } from "./tokenStore.js";

export class OAuthMiddleware {
  constructor(
    private readonly tokenStore: TokenStore,
    private readonly baseURL: string,
  ) {}

  /**
   * Validate the Bearer token on an incoming request.
   * Returns the token claims on success, or null if missing/invalid.
   */
  validate(req: IncomingMessage): TokenClaims | null {
    const token = extractBearerToken(req);
    if (!token) return null;
    return this.tokenStore.validate(token) ?? null;
  }

  /** Send a 401 response with the correct WWW-Authenticate header. */
  unauthorized(res: ServerResponse): void {
    const wwwAuth = `Bearer resource_metadata="${this.baseURL}/.well-known/oauth-protected-resource"`;
    res.writeHead(401, {
      "Content-Type": "application/json",
      "WWW-Authenticate": wwwAuth,
    });
    res.end(JSON.stringify({ error: "unauthorized" }));
  }
}

// ── exported helpers used in src/sse.ts ──────────────────────────────────────

export function extractBearerToken(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

export function extractClientIP(req: IncomingMessage): string {
  const realIP = req.headers["x-real-ip"];
  if (typeof realIP === "string") return realIP;
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  return req.socket?.remoteAddress ?? "unknown";
}
