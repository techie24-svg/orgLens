// Salesforce OAuth 2.0 Web-Server flow with PKCE — the "connect like Workbench" step.
// Token exchange runs server-side because a Connected App's client secret must
// never reach the browser.

import crypto from "node:crypto";

export const OAUTH_SCOPES = ["api", "refresh_token", "web"];

export interface OAuthEnv {
  clientId: string;
  clientSecret: string;
}

export function readOAuthEnv(): OAuthEnv {
  const clientId = process.env.SF_CLIENT_ID;
  const clientSecret = process.env.SF_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("SF_CLIENT_ID / SF_CLIENT_SECRET are not set");
  }
  return { clientId, clientSecret };
}

/** Resolve the OAuth callback URL, honoring an explicit override or the request host. */
export function resolveRedirectUri(req: any): string {
  if (process.env.OAUTH_REDIRECT_URI) return process.env.OAUTH_REDIRECT_URI;
  const host = String(req.headers["x-forwarded-host"] ?? req.headers.host ?? "");
  const fwdProto = String(req.headers["x-forwarded-proto"] ?? "").split(",")[0].trim();
  const isLocal = /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host);
  const proto = fwdProto || (isLocal ? "http" : "https");
  return `${proto}://${host}/api/oauth/callback`;
}

/** Normalize a login-host choice into a full Salesforce authorize origin. */
export function normalizeLoginHost(input: string | undefined): string {
  const v = (input ?? "https://login.salesforce.com").trim();
  if (v === "login" || v === "production") return "https://login.salesforce.com";
  if (v === "test" || v === "sandbox") return "https://test.salesforce.com";
  if (/^https?:\/\//.test(v)) return v.replace(/\/+$/, "");
  // Bare My Domain, e.g. "acme" or "acme.my.salesforce.com"
  if (v.includes(".")) return `https://${v.replace(/\/+$/, "")}`;
  return `https://${v}.my.salesforce.com`;
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(64).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export function buildAuthorizeUrl(opts: {
  loginHost: string;
  clientId: string;
  redirectUri: string;
  state: string;
  challenge: string;
}): string {
  const p = new URLSearchParams({
    response_type: "code",
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    scope: OAUTH_SCOPES.join(" "),
    state: opts.state,
    code_challenge: opts.challenge,
    code_challenge_method: "S256",
  });
  return `${opts.loginHost}/services/oauth2/authorize?${p.toString()}`;
}

export interface TokenResponse {
  access_token: string;
  instance_url: string;
  id: string;
  token_type: string;
  issued_at: string;
}

export async function exchangeCodeForToken(opts: {
  loginHost: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
  clientId: string;
  clientSecret: string;
}): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: opts.code,
    client_id: opts.clientId,
    client_secret: opts.clientSecret,
    redirect_uri: opts.redirectUri,
    code_verifier: opts.codeVerifier,
  });
  const res = await fetch(`${opts.loginHost}/services/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }
  return (await res.json()) as TokenResponse;
}
