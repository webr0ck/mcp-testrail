export interface OIDCConfig {
  clientId: string;
  clientSecret: string;
  authorizeURL: string;
  tokenURL: string;
  baseURL: string;
}

/**
 * Load OIDC configuration from environment variables.
 * Throws if any required variable is missing, allowing callers
 * to gracefully disable OAuth2 when it is not configured.
 */
export function oidcConfigFromEnv(): OIDCConfig {
  const clientId = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const authorizeURL = process.env.OIDC_AUTHORIZE_URL;
  const tokenURL = process.env.OIDC_TOKEN_URL;
  const baseURL = process.env.MCP_SERVER_BASE_URL;

  const missing = (
    [
      ["OIDC_CLIENT_ID", clientId],
      ["OIDC_CLIENT_SECRET", clientSecret],
      ["OIDC_AUTHORIZE_URL", authorizeURL],
      ["OIDC_TOKEN_URL", tokenURL],
      ["MCP_SERVER_BASE_URL", baseURL],
    ] as [string, string | undefined][]
  )
    .filter(([, v]) => !v)
    .map(([k]) => k);

  if (missing.length > 0) {
    throw new Error(
      `OAuth2 not configured: missing env vars: ${missing.join(", ")}`,
    );
  }

  return {
    clientId: clientId!,
    clientSecret: clientSecret!,
    authorizeURL: authorizeURL!,
    tokenURL: tokenURL!,
    baseURL: baseURL!,
  };
}
