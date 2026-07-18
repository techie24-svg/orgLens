// GET /api/session — report whether an org is connected, without leaking the token.

import { getSession } from "./_lib/session.js";

export default function handler(req: any, res: any) {
  const s = getSession(req);
  res.setHeader("Content-Type", "application/json");
  // Which build is actually serving (Vercel injects the commit SHA). Lets us
  // confirm a deploy went live instead of guessing.
  const deployedCommit = (process.env.VERCEL_GIT_COMMIT_SHA ?? "").slice(0, 7) || "local";
  if (!s) {
    res.end(JSON.stringify({ connected: false, deployedCommit }));
    return;
  }
  let host = s.instanceUrl;
  try { host = new URL(s.instanceUrl).host; } catch { /* keep raw */ }
  res.end(JSON.stringify({ connected: true, instanceHost: host, issuedAt: s.issuedAt, deployedCommit }));
}
