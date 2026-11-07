import { randomBytes } from "node:crypto";

export interface TokenClaims {
  sub: string;
  username: string;
  accessToken: string;
  idToken: string;
  clientId: string;
  issuedAt: Date;
  expiresAt: Date;
}

const TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes

export class TokenStore {
  private readonly tokens = new Map<string, TokenClaims>();

  constructor() {
    // Reap expired tokens every 5 minutes; unref so it doesn't keep process alive
    const t = setInterval(() => this.reap(), 5 * 60 * 1000);
    if (typeof t.unref === "function") t.unref();
  }

  issue(
    claims: Omit<TokenClaims, "issuedAt" | "expiresAt">,
  ): string {
    const token = randomBytes(32).toString("base64url");
    const now = new Date();
    this.tokens.set(token, {
      ...claims,
      issuedAt: now,
      expiresAt: new Date(now.getTime() + TOKEN_TTL_MS),
    });
    return token;
  }

  validate(token: string): TokenClaims | undefined {
    const claims = this.tokens.get(token);
    if (!claims) return undefined;
    if (Date.now() > claims.expiresAt.getTime()) {
      this.tokens.delete(token);
      return undefined;
    }
    return claims;
  }

  revoke(token: string): void {
    this.tokens.delete(token);
  }

  private reap(): void {
    const now = Date.now();
    for (const [token, claims] of this.tokens) {
      if (now > claims.expiresAt.getTime()) {
        this.tokens.delete(token);
      }
    }
  }
}
