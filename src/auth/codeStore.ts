import { randomBytes } from "node:crypto";
import type { TokenClaims } from "./tokenStore.js";

export interface CodeEntry {
  claims: Omit<TokenClaims, "issuedAt" | "expiresAt">;
  codeChallenge: string;
  redirectURI: string;
  expiresAt: Date;
}

const CODE_TTL_MS = 2 * 60 * 1000; // 2 minutes

export class CodeStore {
  private readonly entries = new Map<string, CodeEntry>();

  issue(
    claims: Omit<TokenClaims, "issuedAt" | "expiresAt">,
    codeChallenge: string,
    redirectURI: string,
  ): string {
    const code = randomBytes(32).toString("base64url");
    this.entries.set(code, {
      claims,
      codeChallenge,
      redirectURI,
      expiresAt: new Date(Date.now() + CODE_TTL_MS),
    });
    return code;
  }

  /** One-time consume — prevents replay attacks. */
  consume(code: string): CodeEntry | undefined {
    const entry = this.entries.get(code);
    if (!entry) return undefined;
    this.entries.delete(code);
    if (Date.now() > entry.expiresAt.getTime()) return undefined;
    return entry;
  }
}
