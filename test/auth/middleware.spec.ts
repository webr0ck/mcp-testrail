import { describe, it, expect } from "vitest";
import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import {
  OAuthMiddleware,
  extractBearerToken,
  extractClientIP,
} from "../../src/auth/middleware.js";
import { TokenStore } from "../../src/auth/tokenStore.js";

function makeReq(headers: Record<string, string> = {}): IncomingMessage {
  const socket = new Socket();
  const req = new IncomingMessage(socket);
  for (const [k, v] of Object.entries(headers)) {
    req.headers[k.toLowerCase()] = v;
  }
  return req;
}

describe("extractBearerToken", () => {
  it("extracts a valid Bearer token", () => {
    const req = makeReq({ Authorization: "Bearer mytoken123" });
    expect(extractBearerToken(req)).toBe("mytoken123");
  });

  it("returns null when header is missing", () => {
    const req = makeReq();
    expect(extractBearerToken(req)).toBeNull();
  });

  it("returns null for wrong scheme", () => {
    const req = makeReq({ Authorization: "Basic abc123" });
    expect(extractBearerToken(req)).toBeNull();
  });

  it("returns null for lowercase bearer", () => {
    const req = makeReq({ Authorization: "bearer mytoken" });
    expect(extractBearerToken(req)).toBeNull();
  });
});

describe("extractClientIP", () => {
  it("reads X-Real-IP header", () => {
    const req = makeReq({ "X-Real-IP": "10.0.0.1" });
    expect(extractClientIP(req)).toBe("10.0.0.1");
  });

  it("reads first X-Forwarded-For entry", () => {
    const req = makeReq({ "X-Forwarded-For": "192.168.1.1, 10.0.0.2" });
    expect(extractClientIP(req)).toBe("192.168.1.1");
  });
});

describe("OAuthMiddleware", () => {
  it("returns null when token is missing", () => {
    const store = new TokenStore();
    const mw = new OAuthMiddleware(store, "https://mcp.example.com");
    const req = makeReq();
    expect(mw.validate(req)).toBeNull();
  });

  it("returns null for an invalid token", () => {
    const store = new TokenStore();
    const mw = new OAuthMiddleware(store, "https://mcp.example.com");
    const req = makeReq({ Authorization: "Bearer invalid-token" });
    expect(mw.validate(req)).toBeNull();
  });

  it("returns claims for a valid token", () => {
    const store = new TokenStore();
    const token = store.issue({
      sub: "user-1",
      username: "alice",
      accessToken: "at",
      idToken: "idt",
      clientId: "cli",
    });
    const mw = new OAuthMiddleware(store, "https://mcp.example.com");
    const req = makeReq({ Authorization: `Bearer ${token}` });
    const claims = mw.validate(req);
    expect(claims).not.toBeNull();
    expect(claims!.sub).toBe("user-1");
  });
});
