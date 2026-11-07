export interface PKCEEntry {
  codeChallenge: string;
  redirectURI: string;
  createdAt: Date;
}

const PKCE_TTL_MS = 10 * 60 * 1000; // 10 minutes

export class PKCEStore {
  private readonly entries = new Map<string, PKCEEntry>();

  constructor() {
    const t = setInterval(() => this.reap(), 5 * 60 * 1000);
    if (typeof t.unref === "function") t.unref();
  }

  store(state: string, codeChallenge: string, redirectURI: string): void {
    this.entries.set(state, {
      codeChallenge,
      redirectURI,
      createdAt: new Date(),
    });
  }

  /** Atomic load-and-delete to prevent replay attacks. */
  consume(state: string): PKCEEntry | undefined {
    const entry = this.entries.get(state);
    if (!entry) return undefined;
    this.entries.delete(state);
    if (Date.now() - entry.createdAt.getTime() > PKCE_TTL_MS) return undefined;
    return entry;
  }

  private reap(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) {
      if (now - entry.createdAt.getTime() > PKCE_TTL_MS) {
        this.entries.delete(key);
      }
    }
  }
}
