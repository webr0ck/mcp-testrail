import { describe, it, expect } from "vitest";
import { CodeStore } from "../../src/auth/codeStore.js";

const baseClaims = {
  sub: "user-1",
  username: "alice",
  accessToken: "at",
  idToken: "idt",
  clientId: "cli",
};

describe("CodeStore", () => {
  it("issues and consumes a code", () => {
    const store = new CodeStore();
    const code = store.issue(baseClaims, "challenge-abc", "https://client.example.com/cb");

    expect(code).toBeTruthy();
    const entry = store.consume(code);
    expect(entry).not.toBeUndefined();
    expect(entry!.claims.sub).toBe("user-1");
    expect(entry!.codeChallenge).toBe("challenge-abc");
    expect(entry!.redirectURI).toBe("https://client.example.com/cb");
  });

  it("prevents replay: second consume returns undefined", () => {
    const store = new CodeStore();
    const code = store.issue(baseClaims, "ch", "https://example.com/cb");

    expect(store.consume(code)).not.toBeUndefined();
    expect(store.consume(code)).toBeUndefined();
  });

  it("returns undefined for unknown code", () => {
    const store = new CodeStore();
    expect(store.consume("nonexistent")).toBeUndefined();
  });

  it("rejects expired codes", () => {
    const store = new CodeStore();
    const code = store.issue(baseClaims, "ch", "https://example.com/cb");

    // Manually expire
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const entries = (store as any).entries as Map<string, { expiresAt: Date }>;
    entries.get(code)!.expiresAt = new Date(Date.now() - 1000);

    expect(store.consume(code)).toBeUndefined();
  });
});
