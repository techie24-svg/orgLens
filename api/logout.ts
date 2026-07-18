// POST|GET /api/logout — drop the session cookie (revokes local access; the org
// token itself expires on its own schedule).

import { clearSession } from "./_lib/session.js";

export default function handler(req: any, res: any) {
  clearSession(req, res);
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ connected: false }));
}
