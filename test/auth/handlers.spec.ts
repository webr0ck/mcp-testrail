import { describe, it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { Handlers } from "../../src/auth/handlers.js";
import { PKCEStore } from "../../src/auth/pkceStore.js";
import { CodeStore } from "../../src/auth/codeStore.js";
import { TokenStore } from "../../src/auth/tokenStore.js";
import type { OIDCConfig } from "../../src/auth/config.js";
import type { OIDCValidator } from "../../src/auth/oidcValidator.js";

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest().toString("base64url");
}

function makeHandlers(baseURL = "https://mcp.example.com"): Handlers {
  const cfg: OIDCConfig = {
    clientId: "test-client",
    clientSecret: "test-secret",
    authorizeURL: "https://idp.example.com/authorize",
    tokenURL: "https://idp.example.com/token",
    baseURL,
  };
  const validator = {
    exchangeCode: vi.fn(),
    validateIDToken: vi.fn(),
  } as unknown as OIDCValidator;

  return new Handlers(
    cfg,
    new PKCEStore(),
    new CodeStore(),
    new TokenStore(),
    validator,
  );
}

function makeReq(method: string, path: string): IncomingMessage {
  const req = new IncomingMessage(new Socket());
  req.method = method;
  req.url = path;
  req.headers.host = "mcp.example.com";
  return req;
}

/** Minimal ServerResponse mock that captures status code, headers, and body. */
function makeRes(): {
  res: ServerResponse;
  statusCode: () => number;
  headers: () => Record<string, string>;
  body: () => string;
} {
  let code = 0;
  const hdrs: Record<string, string> = {};
  let body = "";

  const res = {
    statusCode: 0,
    writeHead(c: number, h?: unknown) {
      code = c;
      if (h && typeof h === "object") Object.assign(hdrs, h);
      return res;
    },
    end(data?: unknown) {
      if (typeof data === "string") body = data;
      return res;
    },
    getHeader: () => undefined,
    setHeader: () => res,
    headersSent: false,
  } as unknown as ServerResponse;

  return {
    res,
    statusCode: () => code,
    headers: () => hdrs,
    body: () => body,
  };
}

/** Push a string body onto an IncomingMessage via events. */
function pushBody(req: IncomingMessage, body: string): void {
  setImmediate(() => {
    req.emit("data", Buffer.from(body));
    req.emit("end");
  });
}

describe("Handlers", () => {
  describe("wellKnownProtectedResource", () => {
    it("returns resource metadata JSON", () => {
      const h = makeHandlers();
      const { res, statusCode, body } = makeRes();
      h.wellKnownProtectedResource(makeReq("GET", "/"), res);

      expect(statusCode()).toBe(200);
      const parsed = JSON.parse(body());
      expect(parsed.resource).toBe("https://mcp.example.com");
    });
  });

  describe("wellKnownAuthServer", () => {
    it("returns authorization server metadata JSON", () => {
      const h = makeHandlers();
      const { res, statusCode, body } = makeRes();
      h.wellKnownAuthServer(makeReq("GET", "/"), res);

      expect(statusCode()).toBe(200);
      const parsed = JSON.parse(body());
      expect(parsed.issuer).toBe("https://mcp.example.com");
      expect(parsed.authorization_endpoint).toBe(
        "https://mcp.example.com/authorize",
      );
    });
  });

  describe("authorize", () => {
    it("redirects to upstream OIDC for a valid request", () => {
      const h = makeHandlers();
      const verifier = "my-code-verifier-string-at-least-43-chars-longx";
      const challenge = pkceChallenge(verifier);
      const params = new URLSearchParams({
        response_type: "code",
        client_id: "test-client",
        redirect_uri: "https://client.example.com/cb",
        state: "state-abc",
        code_challenge_method: "S256",
        code_challenge: challenge,
      });
      const { res, statusCode, headers } = makeRes();
      h.authorize(makeReq("GET", `/authorize?${params.toString()}`), res);

      expect(statusCode()).toBe(302);
      expect(headers()["Location"]).toContain("idp.example.com");
      expect(headers()["Location"]).toContain("state-abc");
    });

    it("stores state in PKCEStore after valid authorize", () => {
      const h = makeHandlers();
      const verifier = "my-code-verifier-string-at-least-43-chars-longx";
      const challenge = pkceChallenge(verifier);
      const params = new URLSearchParams({
        response_type: "code",
        client_id: "test-client",
        redirect_uri: "https://client.example.com/cb",
        state: "state-xyz",
        code_challenge_method: "S256",
        code_challenge: challenge,
      });
      const { res } = makeRes();
      h.authorize(makeReq("GET", `/authorize?${params.toString()}`), res);

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const pkceStore: PKCEStore = (h as any).pkceStore;
      const entry = pkceStore.consume("state-xyz");
      expect(entry).not.toBeUndefined();
      expect(entry!.codeChallenge).toBe(challenge);
    });

    it("redirects with error when code_challenge is missing", () => {
      const h = makeHandlers();
      const params = new URLSearchParams({
        response_type: "code",
        client_id: "test-client",
        redirect_uri: "https://client.example.com/cb",
        state: "state-abc",
        code_challenge_method: "S256",
      });
      const { res, statusCode, headers } = makeRes();
      h.authorize(makeReq("GET", `/authorize?${params.toString()}`), res);

      expect(statusCode()).toBe(302);
      expect(headers()["Location"]).toContain("error=");
    });

    it("redirects with error for wrong client_id", () => {
      const h = makeHandlers();
      const params = new URLSearchParams({
        response_type: "code",
        client_id: "wrong-client",
        redirect_uri: "https://client.example.com/cb",
        state: "state-abc",
        code_challenge_method: "S256",
        code_challenge: "abc",
      });
      const { res, statusCode, headers } = makeRes();
      h.authorize(makeReq("GET", `/authorize?${params.toString()}`), res);

      expect(statusCode()).toBe(302);
      expect(headers()["Location"]).toContain("error=unauthorized_client");
    });
  });

  describe("token", () => {
    it("returns 400 for unsupported grant_type", async () => {
      const h = makeHandlers();
      const bodyStr = "grant_type=implicit";
      const req = makeReq("POST", "/token");
      pushBody(req, bodyStr);
      const { res, statusCode, body } = makeRes();
      await h.token(req, res);

      expect(statusCode()).toBe(400);
      expect(JSON.parse(body()).error).toBe("unsupported_grant_type");
    });

    it("returns 400 for invalid_grant when code is unknown", async () => {
      const h = makeHandlers();
      const bodyStr = "grant_type=authorization_code&code=bad-code&code_verifier=verifier";
      const req = makeReq("POST", "/token");
      pushBody(req, bodyStr);
      const { res, statusCode, body } = makeRes();
      await h.token(req, res);

      expect(statusCode()).toBe(400);
      expect(JSON.parse(body()).error).toBe("invalid_grant");
    });

    it("returns 400 when PKCE verification fails", async () => {
      const h = makeHandlers();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const codeStore: CodeStore = (h as any).codeStore;
      const code = codeStore.issue(
        { sub: "u", username: "u", accessToken: "", idToken: "", clientId: "c" },
        pkceChallenge("correct-verifier-string-at-least-43-chars-longx"),
        "https://example.com/cb",
      );

      const bodyStr = `grant_type=authorization_code&code=${code}&code_verifier=wrong-verifier`;
      const req = makeReq("POST", "/token");
      pushBody(req, bodyStr);
      const { res, statusCode, body } = makeRes();
      await h.token(req, res);

      expect(statusCode()).toBe(400);
      expect(JSON.parse(body()).error).toBe("invalid_grant");
    });

    it("issues a bearer token on valid exchange", async () => {
      const h = makeHandlers();
      const verifier = "correct-verifier-string-at-least-43-chars-longx";
      const challenge = pkceChallenge(verifier);

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const codeStore: CodeStore = (h as any).codeStore;
      const code = codeStore.issue(
        { sub: "user-42", username: "alice", accessToken: "at", idToken: "idt", clientId: "test-client" },
        challenge,
        "https://client.example.com/cb",
      );

      const bodyStr = `grant_type=authorization_code&code=${code}&code_verifier=${verifier}`;
      const req = makeReq("POST", "/token");
      pushBody(req, bodyStr);
      const { res, statusCode, body } = makeRes();
      await h.token(req, res);

      expect(statusCode()).toBe(200);
      const parsed = JSON.parse(body());
      expect(parsed.access_token).toBeTruthy();
      expect(parsed.token_type).toBe("bearer");
    });
  });
});
