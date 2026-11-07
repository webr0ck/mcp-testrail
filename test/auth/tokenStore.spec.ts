import { describe, it, expect } from "vitest";
import { TokenStore } from "../../src/auth/tokenStore.js";

describe("TokenStore", () => {
  it("issues and validates a token", () => {
    const store = new TokenStore();
    const token = store.issue({
      sub: "user-1",
      username: "alice",
      accessToken: "at",
      idToken: "idt",
      clientId: "cli",
    });

    expect(token).toBeTruthy();
    const claims = store.validate(token);
    expect(claims).not.toBeUndefined();
    expect(claims!.sub).toBe("user-1");
    expect(claims!.username).toBe("alice");
  });

  it("returns undefined for an unknown token", () => {
    const store = new TokenStore();
    expect(store.validate("nonexistent")).toBeUndefined();
  });

  it("returns undefined for a revoked token", () => {
    const store = new TokenStore();
    const token = store.issue({
      sub: "u",
      username: "u",
      accessToken: "",
      idToken: "",
      clientId: "c",
    });
    store.revoke(token);
    expect(store.validate(token)).toBeUndefined();
  });

  it("returns undefined for an expired token", () => {
    const store = new TokenStore();
    const token = store.issue({
      sub: "u",
      username: "u",
      accessToken: "",
      idToken: "",
      clientId: "c",
    });

    // Manually expire by mutating the internal map
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tokens = (store as any).tokens as Map<string, { expiresAt: Date }>;
    tokens.get(token)!.expiresAt = new Date(Date.now() - 1000);

    expect(store.validate(token)).toBeUndefined();
  });

  it("issues unique tokens", () => {
    const store = new TokenStore();
    const t1 = store.issue({ sub: "a", username: "a", accessToken: "", idToken: "", clientId: "c" });
    const t2 = store.issue({ sub: "b", username: "b", accessToken: "", idToken: "", clientId: "c" });
    expect(t1).not.toBe(t2);
  });
});
