#!/usr/bin/env node
import http from "node:http";
import { randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import "dotenv/config";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { TestRailClient, type TestRailClientConfig } from "./client/api/index.js";
import { registerAllTools } from "./server/api/index.js";
import { oidcConfigFromEnv } from "./auth/config.js";
import { PKCEStore } from "./auth/pkceStore.js";
import { CodeStore } from "./auth/codeStore.js";
import { TokenStore } from "./auth/tokenStore.js";
import { OIDCValidator } from "./auth/oidcValidator.js";
import { Handlers } from "./auth/handlers.js";
import { OAuthMiddleware, extractClientIP } from "./auth/middleware.js";
import { AuditLogger } from "./auth/audit/audit.js";
import type { TokenClaims } from "./auth/tokenStore.js";

// ── TestRail client setup (unchanged) ────────────────────────────────────────

if (
  !process.env.TESTRAIL_URL ||
  !process.env.TESTRAIL_USERNAME ||
  !process.env.TESTRAIL_API_KEY
) {
  throw new Error(
    "TESTRAIL_URL, TESTRAIL_USERNAME, and TESTRAIL_API_KEY must be set",
  );
}

const rawURL = process.env.TESTRAIL_URL;
const testrailBaseURL = rawURL.endsWith("/index.php?/")
  ? rawURL
  : rawURL.endsWith("/")
    ? `${rawURL}index.php?/`
    : `${rawURL}/index.php?/`;

const testRailConfig: TestRailClientConfig = {
  baseURL: testrailBaseURL,
  auth: {
    username: process.env.TESTRAIL_USERNAME,
    password: process.env.TESTRAIL_API_KEY, // API key — never replaced by OAuth tokens
  },
};

const testRailClient = new TestRailClient(testRailConfig);

// ── OAuth2 setup (gracefully disabled when env vars absent) ──────────────────

let oidcHandlers: Handlers | null = null;
let oauthMW: OAuthMiddleware | null = null;
let auditLogger: AuditLogger | null = null;

try {
  const oidcCfg = oidcConfigFromEnv();
  const pkceStore = new PKCEStore();
  const codeStore = new CodeStore();
  const tokenStore = new TokenStore();
  const validator = new OIDCValidator(oidcCfg);

  oidcHandlers = new Handlers(oidcCfg, pkceStore, codeStore, tokenStore, validator);
  oauthMW = new OAuthMiddleware(tokenStore, oidcCfg.baseURL);

  const logPath = process.env.AUDIT_LOG_PATH ?? "/tmp/audit.log";
  auditLogger = new AuditLogger(
    logPath,
    "mcp-testrail",
    process.env.HOSTNAME ?? "",
  );

  console.error("OAuth2 authentication enabled");
} catch (err) {
  console.error(
    "OAuth2 not configured, running in unauthenticated mode:",
    (err as Error).message,
  );
}

// ── SSE transport registry ────────────────────────────────────────────────────

// Map sessionId → {transport, claims}
const sessions = new Map<
  string,
  { transport: SSEServerTransport; claims: TokenClaims | null }
>();

// ── HTTP request handler ──────────────────────────────────────────────────────

const port = parseInt(process.env.PORT ?? "3000", 10);

const srv = http.createServer(async (req, res) => {
  const baseForParsing = `http://localhost:${port}`;
  const reqURL = new URL(req.url ?? "/", baseForParsing);
  const { pathname } = reqURL;

  try {
    // ── OAuth2 endpoints (no auth required) ──────────────────────────────

    if (oidcHandlers) {
      if (pathname === "/.well-known/oauth-protected-resource" && req.method === "GET") {
        oidcHandlers.wellKnownProtectedResource(req, res);
        return;
      }

      if (pathname === "/.well-known/oauth-authorization-server" && req.method === "GET") {
        oidcHandlers.wellKnownAuthServer(req, res);
        return;
      }

      if (pathname === "/authorize" && req.method === "GET") {
        oidcHandlers.authorize(req, res);
        return;
      }

      if (pathname === "/callback" && req.method === "GET") {
        await oidcHandlers.callback(req, res);
        return;
      }

      if (pathname === "/token" && req.method === "POST") {
        await oidcHandlers.token(req, res);
        return;
      }
    }

    // ── SSE endpoint ──────────────────────────────────────────────────────

    if (pathname === "/sse" && req.method === "GET") {
      // Enforce authentication when OAuth2 is configured
      let claims: TokenClaims | null = null;
      if (oauthMW) {
        claims = oauthMW.validate(req);
        if (!claims) {
          oauthMW.unauthorized(res);
          return;
        }
      }

      // One McpServer per SSE connection (SDK design; tools are stateless)
      const mcpServer = new McpServer({
        name: "TestRail MCP Server",
        version: "1.0.0",
      });
      registerAllTools(mcpServer, testRailClient);

      const transport = new SSEServerTransport("/messages", res);

      sessions.set(transport.sessionId, { transport, claims });

      transport.onclose = () => {
        sessions.delete(transport.sessionId);
      };

      await mcpServer.connect(transport);
      return;
    }

    // ── Messages endpoint ─────────────────────────────────────────────────

    if (pathname === "/messages" && req.method === "POST") {
      const sessionId = reqURL.searchParams.get("sessionId") ?? "";
      const session = sessions.get(sessionId);

      if (!session) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "session_not_found" }));
        return;
      }

      // Read body so we can emit an audit event before forwarding
      const body = await readBody(req);

      emitAuditEvent(body, session.claims, req, auditLogger);

      // Re-stream the body to the transport via a synthetic Readable
      const fakeReq = makeFakeReq(req, body);
      await session.transport.handlePostMessage(fakeReq as http.IncomingMessage, res);
      return;
    }

    // ── Health check ──────────────────────────────────────────────────────

    if (pathname === "/healthz") {
      res.writeHead(200);
      res.end("ok");
      return;
    }

    res.writeHead(404);
    res.end();
  } catch (err) {
    console.error("Unhandled request error:", err);
    if (!res.headersSent) {
      res.writeHead(500);
      res.end();
    }
  }
});

srv.listen(port, () => {
  console.error(`TestRail MCP Server (SSE/OAuth2 mode) listening on port ${port}`);
});

// ── helpers ───────────────────────────────────────────────────────────────────

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk: Buffer) => {
      data += chunk.toString();
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

/**
 * Build a fake IncomingMessage-like object that replays an already-read body.
 * The SSEServerTransport reads the body via 'data'/'end' events on the request,
 * so we wrap the buffered string in a Readable.
 */
function makeFakeReq(
  original: http.IncomingMessage,
  body: string,
): Readable & { headers: typeof original.headers; method: string | undefined; url: string | undefined } {
  const readable = new Readable({ read() {} });
  readable.push(body);
  readable.push(null);

  return Object.assign(readable, {
    headers: original.headers,
    method: original.method,
    url: original.url,
  });
}

function emitAuditEvent(
  body: string,
  claims: TokenClaims | null,
  req: http.IncomingMessage,
  logger: AuditLogger | null,
): void {
  if (!logger || !claims) return;

  try {
    const rpc = JSON.parse(body) as {
      method?: string;
      params?: { name?: string };
      id?: string | number;
    };

    if (rpc.method !== "tools/call") return;

    const toolName = rpc.params?.name ?? "unknown";
    const requestId = String(rpc.id ?? "");
    const correlationId = randomUUID();
    const sourceIP = extractClientIP(req);

    const event = logger.newToolCallEvent(
      toolName,
      claims.sub,
      claims.username,
      claims.clientId,
      sourceIP,
      requestId,
      correlationId,
      "success",
    );
    logger.log(event);
  } catch {
    // Body is not JSON or not a tool call — skip audit
  }
}
