// GET /api/oauth/callback?code=...&state=...
// Salesforce redirects here after the user authorizes. We verify state, exchange
// the code (+ PKCE verifier) for a token server-side, store it in an encrypted
// session cookie, and bounce back to the app.

import { exchangeCodeForToken, readOAuthEnv } from "../_lib/oauth.js";
import { clearOAuthState, getOAuthState, setSession } from "../_lib/session.js";

function redirect(res: any, to: string) {
  res.statusCode = 302;
  res.setHeader("Location", to);
  res.end();
}

export default async function handler(req: any, res: any) {
  const err = req.query?.error;
  if (err) return redirect(res, `/?error=${encodeURIComponent(String(req.query?.error_description ?? err))}`);

  const code = req.query?.code;
  const state = req.query?.state;
  const saved = getOAuthState(req);
  clearOAuthState(req, res);

  if (!code || !saved || saved.state !== state) {
    return redirect(res, `/?error=${encodeURIComponent("Invalid or expired OAuth state — please retry.")}`);
  }

  try {
    const { clientId, clientSecret } = readOAuthEnv();
    const token = await exchangeCodeForToken({
      loginHost: saved.loginHost,
      code: String(code),
      redirectUri: saved.redirectUri,
      codeVerifier: saved.codeVerifier,
      clientId,
      clientSecret,
    });
    setSession(req, res, {
      accessToken: token.access_token,
      instanceUrl: token.instance_url,
      identityUrl: token.id,
      issuedAt: Date.now(),
    });
    redirect(res, "/?connected=1");
  } catch (e: any) {
    redirect(res, `/?error=${encodeURIComponent(e?.message ?? "Token exchange failed")}`);
  }
}
