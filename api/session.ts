// GET /api/session — report whether an org is connected, without leaking the token.

import { getSession } from "./_lib/session.js";

export default function handler(req: any, res: any) {
  const s = getSession(req);
  res.setHeader("Content-Type", "application/json");
  if (!s) {
    res.end(JSON.stringify({ connected: false }));
    return;
  }
  let host = s.instanceUrl;
  try { host = new URL(s.instanceUrl).host; } catch { /* keep raw */ }
  res.end(JSON.stringify({ connected: true, instanceHost: host, issuedAt: s.issuedAt }));
}
