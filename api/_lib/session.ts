// Stateless session for a serverless (Vercel) deployment.
//
// Workbench-style tools keep the org access token server-side. Because Vercel
// functions are stateless, we store the token in an AES-256-GCM-encrypted,
// httpOnly cookie instead of a database. The browser never sees the token.

import crypto from "node:crypto";

const SESSION_COOKIE = "orglens_session";
const OAUTH_COOKIE = "orglens_oauth";

export interface Session {
  accessToken: string;
  instanceUrl: string;
  /** OAuth identity URL of the authenticated user. */
  identityUrl?: string;
  /** Long-lived refresh token, used to mint a fresh access token per scan. */
  refreshToken?: string;
  /** Login host used at authorization (needed for the refresh grant). */
  loginHost?: string;
  issuedAt: number;
}

/** Short-lived state carried across the OAuth redirect (CSRF + PKCE). */
export interface OAuthState {
  state: string;
  codeVerifier: string;
  loginHost: string;
  redirectUri: string;
}

function key(): Buffer {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET is not set");
  return crypto.createHash("sha256").update(secret).digest();
}

function encrypt(payload: unknown): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([
    cipher.update(JSON.stringify(payload), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, data]).toString("base64url");
}

function decrypt<T>(token: string): T | null {
  try {
    const raw = Buffer.from(token, "base64url");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const data = raw.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key(), iv);
    decipher.setAuthTag(tag);
    const out = Buffer.concat([decipher.update(data), decipher.final()]);
    return JSON.parse(out.toString("utf8")) as T;
  } catch {
    return null;
  }
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function serializeCookie(
  name: string,
  value: string,
  opts: { maxAge?: number; secure: boolean; httpOnly?: boolean }
): string {
  const bits = [`${name}=${encodeURIComponent(value)}`, "Path=/", "SameSite=Lax"];
  if (opts.httpOnly !== false) bits.push("HttpOnly");
  if (opts.secure) bits.push("Secure");
  if (opts.maxAge !== undefined) bits.push(`Max-Age=${opts.maxAge}`);
  return bits.join("; ");
}

function isSecure(req: { headers: Record<string, unknown> }): boolean {
  const proto = String(req.headers["x-forwarded-proto"] ?? "");
  return proto.split(",")[0].trim() === "https";
}

function appendCookie(res: { getHeader: Function; setHeader: Function }, cookie: string) {
  const existing = res.getHeader("Set-Cookie");
  if (!existing) res.setHeader("Set-Cookie", cookie);
  else if (Array.isArray(existing)) res.setHeader("Set-Cookie", [...existing, cookie]);
  else res.setHeader("Set-Cookie", [existing as string, cookie]);
}

export function setSession(req: any, res: any, session: Session) {
  appendCookie(
    res,
    serializeCookie(SESSION_COOKIE, encrypt(session), { maxAge: 60 * 60 * 8, secure: isSecure(req) })
  );
}

export function getSession(req: any): Session | null {
  const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  return raw ? decrypt<Session>(raw) : null;
}

export function clearSession(req: any, res: any) {
  appendCookie(res, serializeCookie(SESSION_COOKIE, "", { maxAge: 0, secure: isSecure(req) }));
}

export function setOAuthState(req: any, res: any, state: OAuthState) {
  appendCookie(
    res,
    serializeCookie(OAUTH_COOKIE, encrypt(state), { maxAge: 600, secure: isSecure(req) })
  );
}

export function getOAuthState(req: any): OAuthState | null {
  const raw = parseCookies(req.headers.cookie)[OAUTH_COOKIE];
  return raw ? decrypt<OAuthState>(raw) : null;
}

export function clearOAuthState(req: any, res: any) {
  appendCookie(res, serializeCookie(OAUTH_COOKIE, "", { maxAge: 0, secure: isSecure(req) }));
}
