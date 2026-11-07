import { describe, it, expect } from "vitest";
import { PKCEStore } from "../../src/auth/pkceStore.js";

describe("PKCEStore", () => {
  it("stores and consumes a PKCE entry", () => {
    const store = new PKCEStore();
    store.store("state-1", "challenge-abc", "https://client.example.com/cb");

    const entry = store.consume("state-1");
    expect(entry).not.toBeUndefined();
    expect(entry!.codeChallenge).toBe("challenge-abc");
    expect(entry!.redirectURI).toBe("https://client.example.com/cb");
  });

  it("prevents replay: second consume returns undefined", () => {
    const store = new PKCEStore();
    store.store("state-2", "ch", "https://example.com/cb");

    expect(store.consume("state-2")).not.toBeUndefined();
    expect(store.consume("state-2")).toBeUndefined();
  });

  it("returns undefined for unknown state", () => {
    const store = new PKCEStore();
    expect(store.consume("no-such-state")).toBeUndefined();
  });

  it("rejects expired entries", () => {
    const store = new PKCEStore();
    store.store("state-3", "ch", "https://example.com/cb");

    // Manually expire
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const entries = (store as any).entries as Map<string, { createdAt: Date }>;
    entries.get("state-3")!.createdAt = new Date(Date.now() - 15 * 60 * 1000);

    expect(store.consume("state-3")).toBeUndefined();
  });
});
