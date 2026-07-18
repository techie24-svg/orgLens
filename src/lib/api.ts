// Thin client for the OrgLens backend (Vercel serverless functions under /api).
// The backend holds the OAuth token; the browser only ever sees session status
// and the resulting snapshot.

import type { OrgSnapshot } from "../types";

export interface SessionInfo {
  connected: boolean;
  instanceHost?: string;
  issuedAt?: number;
}

export async function getSession(): Promise<SessionInfo> {
  try {
    const res = await fetch("/api/session", { headers: { Accept: "application/json" } });
    if (!res.ok) return { connected: false };
    return (await res.json()) as SessionInfo;
  } catch {
    return { connected: false };
  }
}

export async function scanLiveOrg(): Promise<OrgSnapshot> {
  const res = await fetch("/api/scan", { headers: { Accept: "application/json" } });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as any)?.error ?? `Scan failed (${res.status})`);
  }
  return (await res.json()) as OrgSnapshot;
}

/** Redirect the browser into the OAuth web-server flow. */
export function startOAuth(host: string): void {
  window.location.href = `/api/oauth/start?host=${encodeURIComponent(host)}`;
}

export async function logout(): Promise<void> {
  try { await fetch("/api/logout"); } catch { /* ignore */ }
}
