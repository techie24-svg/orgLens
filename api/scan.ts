// GET /api/scan — run a live posture scan against the connected org and return
// a normalized OrgSnapshot (the same shape the MockProvider produces).

import { assembleSnapshot } from "./_lib/salesforce.js";
import { getSession } from "./_lib/session.js";

export default async function handler(req: any, res: any) {
  const s = getSession(req);
  res.setHeader("Content-Type", "application/json");
  if (!s) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: "Not connected" }));
    return;
  }
  try {
    const snapshot = await assembleSnapshot(s.instanceUrl, s.accessToken);
    res.end(JSON.stringify(snapshot));
  } catch (e: any) {
    res.statusCode = 502;
    res.end(JSON.stringify({ error: e?.message ?? "Scan failed" }));
  }
}
