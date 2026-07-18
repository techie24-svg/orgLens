// GET /api/oauth/start?host=login|test|<mydomain>
// Kicks off the OAuth web-server flow: stores PKCE + state in a short-lived
// cookie and redirects the browser to the Salesforce authorize screen.

import crypto from "node:crypto";
import { buildAuthorizeUrl, normalizeLoginHost, pkcePair, readOAuthEnv, resolveRedirectUri } from "../_lib/oauth";
import { setOAuthState } from "../_lib/session";

export default function handler(req: any, res: any) {
  try {
    const { clientId } = readOAuthEnv();
    const loginHost = normalizeLoginHost(req.query?.host);
    const redirectUri = resolveRedirectUri(req);
    const state = crypto.randomBytes(16).toString("base64url");
    const { verifier, challenge } = pkcePair();

    setOAuthState(req, res, { state, codeVerifier: verifier, loginHost, redirectUri });

    const url = buildAuthorizeUrl({ loginHost, clientId, redirectUri, state, challenge });
    res.statusCode = 302;
    res.setHeader("Location", url);
    res.end();
  } catch (e: any) {
    res.statusCode = 500;
    res.setHeader("Content-Type", "text/plain");
    res.end(`OAuth start failed: ${e?.message ?? "unknown error"}`);
  }
}
