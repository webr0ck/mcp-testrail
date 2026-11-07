import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { OIDCConfig } from "./config.js";
import type { PKCEStore } from "./pkceStore.js";
import type { CodeStore } from "./codeStore.js";
import type { TokenStore } from "./tokenStore.js";
import type { OIDCValidator } from "./oidcValidator.js";

export class Handlers {
  constructor(
    private readonly cfg: OIDCConfig,
    private readonly pkceStore: PKCEStore,
    private readonly codeStore: CodeStore,
    private readonly tokenStore: TokenStore,
    private readonly validator: OIDCValidator,
  ) {}

  // RFC 9728: OAuth 2.0 Protected Resource Metadata
  wellKnownProtectedResource(
    _req: IncomingMessage,
    res: ServerResponse,
  ): void {
    const body = JSON.stringify({
      resource: this.cfg.baseURL,
      authorization_servers: [
        `${this.cfg.baseURL}/.well-known/oauth-authorization-server`,
      ],
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(body);
  }

  // RFC 8414: OAuth 2.0 Authorization Server Metadata
  wellKnownAuthServer(_req: IncomingMessage, res: ServerResponse): void {
    const body = JSON.stringify({
      issuer: this.cfg.baseURL,
      authorization_endpoint: `${this.cfg.baseURL}/authorize`,
      token_endpoint: `${this.cfg.baseURL}/token`,
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(body);
  }

  // Step 1: MCP client requests authorization
  authorize(req: IncomingMessage, res: ServerResponse): void {
    const reqURL = new URL(
      req.url!,
      `http://${req.headers.host ?? "localhost"}`,
    );
    const q = reqURL.searchParams;

    const redirectURI = q.get("redirect_uri") ?? "";
    const state = q.get("state");
    const errorRedirect = redirectURI || this.cfg.baseURL;

    if (q.get("response_type") !== "code") {
      oauthError(res, errorRedirect, state, "unsupported_response_type");
      return;
    }
    if (q.get("client_id") !== this.cfg.clientId) {
      oauthError(res, errorRedirect, state, "unauthorized_client");
      return;
    }
    if (!q.get("code_challenge")) {
      oauthError(
        res,
        errorRedirect,
        state,
        "invalid_request",
        "code_challenge required",
      );
      return;
    }
    if (q.get("code_challenge_method") !== "S256") {
      oauthError(
        res,
        errorRedirect,
        state,
        "invalid_request",
        "only S256 supported",
      );
      return;
    }
    if (!state) {
      oauthError(res, errorRedirect, null, "invalid_request", "state required");
      return;
    }
    if (!redirectURI) {
      oauthError(
        res,
        errorRedirect,
        state,
        "invalid_request",
        "redirect_uri required",
      );
      return;
    }

    // Store state → PKCE entry
    this.pkceStore.store(state, q.get("code_challenge")!, redirectURI);

    // Redirect to upstream OIDC provider
    const upstream = new URLSearchParams({
      response_type: "code",
      client_id: this.cfg.clientId,
      redirect_uri: `${this.cfg.baseURL}/callback`,
      scope: "openid profile email",
      state,
    });

    res.writeHead(302, {
      Location: `${this.cfg.authorizeURL}?${upstream.toString()}`,
    });
    res.end();
  }

  // Step 2: OIDC provider redirects back here after user login
  async callback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const reqURL = new URL(
      req.url!,
      `http://${req.headers.host ?? "localhost"}`,
    );
    const q = reqURL.searchParams;

    const code = q.get("code");
    const state = q.get("state");
    const upstreamError = q.get("error");

    if (upstreamError || !code || !state) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: upstreamError ?? "missing_code_or_state",
        }),
      );
      return;
    }

    const pkceEntry = this.pkceStore.consume(state);
    if (!pkceEntry) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_state" }));
      return;
    }

    try {
      const tokenSet = await this.validator.exchangeCode(
        code,
        "", // No code_verifier passed to upstream (MCP server is the OAuth client)
        `${this.cfg.baseURL}/callback`,
      );

      const claims = await this.validator.validateIDToken(tokenSet.idToken);

      const authCode = this.codeStore.issue(
        {
          sub: claims.sub,
          username: claims.username,
          accessToken: tokenSet.accessToken,
          idToken: tokenSet.idToken,
          clientId: this.cfg.clientId,
        },
        pkceEntry.codeChallenge,
        pkceEntry.redirectURI,
      );

      const redirectParams = new URLSearchParams({ code: authCode, state });
      res.writeHead(302, {
        Location: `${pkceEntry.redirectURI}?${redirectParams.toString()}`,
      });
      res.end();
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "server_error",
          error_description: String(err),
        }),
      );
    }
  }

  // Step 3: MCP client exchanges authorization code for bearer token
  async token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readBody(req);
    const params = new URLSearchParams(body);

    if (params.get("grant_type") !== "authorization_code") {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unsupported_grant_type" }));
      return;
    }

    const code = params.get("code");
    if (!code) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "invalid_request",
          error_description: "code required",
        }),
      );
      return;
    }

    const entry = this.codeStore.consume(code);
    if (!entry) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
      return;
    }

    const codeVerifier = params.get("code_verifier") ?? "";
    if (!codeVerifier || !verifyPKCES256(codeVerifier, entry.codeChallenge)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "PKCE verification failed",
        }),
      );
      return;
    }

    const token = this.tokenStore.issue(entry.claims);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        access_token: token,
        token_type: "bearer",
        expires_in: 900,
      }),
    );
  }
}

// ── helpers ──────────────────────────────────────────────────────────────────

function oauthError(
  res: ServerResponse,
  redirectURI: string,
  state: string | null,
  error: string,
  description?: string,
): void {
  const params = new URLSearchParams({ error });
  if (state) params.set("state", state);
  if (description) params.set("error_description", description);
  res.writeHead(302, { Location: `${redirectURI}?${params.toString()}` });
  res.end();
}

function verifyPKCES256(verifier: string, challenge: string): boolean {
  const computed = createHash("sha256")
    .update(verifier)
    .digest()
    .toString("base64url");
  return computed === challenge;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk: Buffer) => {
      data += chunk.toString();
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
