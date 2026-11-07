import { createRemoteJWKSet, jwtVerify } from "jose";
import type { OIDCConfig } from "./config.js";

export interface OIDCTokenSet {
  accessToken: string;
  idToken: string;
}

export interface OIDCClaims {
  sub: string;
  username: string;
}

interface DiscoveryDoc {
  jwks_uri: string;
  issuer: string;
}

interface TokenResponse {
  access_token: string;
  id_token: string;
}

type JWKSFn = ReturnType<typeof createRemoteJWKSet>;

export class OIDCValidator {
  private jwks: JWKSFn | null = null;
  private discoveredIssuer: string | null = null;
  private discoveryPending = false;
  private discoveryPromise: Promise<void> | null = null;

  constructor(private readonly cfg: OIDCConfig) {}

  /**
   * Exchange an authorization code with the upstream OIDC provider.
   * codeVerifier is only included if non-empty (when the MCP server
   * relayed PKCE to the upstream IdP).
   */
  async exchangeCode(
    code: string,
    codeVerifier: string,
    redirectURI: string,
  ): Promise<OIDCTokenSet> {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectURI,
      client_id: this.cfg.clientId,
      client_secret: this.cfg.clientSecret,
    });
    if (codeVerifier) {
      params.set("code_verifier", codeVerifier);
    }

    const resp = await fetch(this.cfg.tokenURL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Token exchange failed: ${resp.status} ${text}`);
    }

    const data = (await resp.json()) as TokenResponse;
    if (!data.access_token) {
      throw new Error("Token exchange: missing access_token in response");
    }

    return { accessToken: data.access_token, idToken: data.id_token ?? "" };
  }

  /**
   * Validate a raw ID token JWT using the upstream JWKS.
   * Returns the subject and preferred username.
   */
  async validateIDToken(idTokenRaw: string): Promise<OIDCClaims> {
    await this.ensureDiscovery();

    const { payload } = await jwtVerify(idTokenRaw, this.jwks!, {
      issuer: this.discoveredIssuer ?? undefined,
    });

    const sub = payload.sub ?? "";
    const username =
      (payload["preferred_username"] as string | undefined) ??
      (payload["email"] as string | undefined) ??
      sub;

    return { sub, username };
  }

  private async ensureDiscovery(): Promise<void> {
    if (this.jwks !== null) return;

    // Deduplicate concurrent discovery calls
    if (this.discoveryPromise) {
      await this.discoveryPromise;
      return;
    }

    this.discoveryPromise = this.discover().finally(() => {
      this.discoveryPromise = null;
    });
    await this.discoveryPromise;
  }

  private async discover(): Promise<void> {
    const discoveryURL = this.buildDiscoveryURL();
    const resp = await fetch(discoveryURL);
    if (!resp.ok) {
      throw new Error(`OIDC discovery failed: ${resp.status} ${discoveryURL}`);
    }
    const doc = (await resp.json()) as DiscoveryDoc;
    this.discoveredIssuer = doc.issuer ?? null;
    this.jwks = createRemoteJWKSet(new URL(doc.jwks_uri));
  }

  private buildDiscoveryURL(): string {
    // Strip /authorize or /oauth2/authorize suffix to get the issuer base
    const base = this.cfg.authorizeURL
      .replace(/\/oauth2\/authorize$/, "")
      .replace(/\/authorize$/, "");
    return `${base}/.well-known/openid-configuration`;
  }
}
