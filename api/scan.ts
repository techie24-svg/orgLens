// GET /api/scan — run a live posture scan against the connected org and return
// a normalized OrgSnapshot (the same shape the MockProvider produces).
//
// Salesforce access tokens are short-lived, so we proactively mint a fresh one
// from the stored refresh token before each scan (and persist it back to the
// session). Without this, scans started long after login fail with
// INVALID_SESSION_ID on every call.

import { assembleSnapshot } from "./_lib/salesforce.js";
import { getSession, setSession } from "./_lib/session.js";
import { readOAuthEnv, refreshAccessToken } from "./_lib/oauth.js";

export default async function handler(req: any, res: any) {
  const s = getSession(req);
  res.setHeader("Content-Type", "application/json");
  if (!s) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: "Not connected" }));
    return;
  }

  let accessToken = s.accessToken;
  let instanceUrl = s.instanceUrl;
  let refreshNote: string | null = null;

  if (s.refreshToken) {
    try {
      const { clientId, clientSecret } = readOAuthEnv();
      const refreshed = await refreshAccessToken({
        loginHost: s.loginHost ?? "https://login.salesforce.com",
        refreshToken: s.refreshToken,
        clientId,
        clientSecret,
      });
      accessToken = refreshed.access_token;
      if (refreshed.instance_url) instanceUrl = refreshed.instance_url;
      setSession(req, res, { ...s, accessToken, instanceUrl, issuedAt: Date.now() });
    } catch (e: any) {
      // Refresh token itself is invalid/expired → the user must reconnect.
      res.statusCode = 401;
      res.end(JSON.stringify({ error: "Session expired — please reconnect.", detail: e?.message }));
      return;
    }
  } else {
    refreshNote = "No refresh token on this session (connected app may not issue one); reconnect if the scan shows expired-session errors.";
  }

  try {
    const snapshot = await assembleSnapshot(instanceUrl, accessToken);
    if (refreshNote) (snapshot._coverage ??= []).unshift(refreshNote);
    res.end(JSON.stringify(snapshot));
  } catch (e: any) {
    res.statusCode = 502;
    res.end(JSON.stringify({ error: e?.message ?? "Scan failed" }));
  }
}
