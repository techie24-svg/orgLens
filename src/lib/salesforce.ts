// Client-side connection helpers.
//
// The real OAuth handshake and live Salesforce API calls run server-side (see
// /api/*), because a Connected App secret and the org access token must never
// live in the browser. On the client we only keep the demo provider and the
// scopes we display in the Connections UI.

import type { OrgSnapshot } from "../types";
import { SAMPLE_ORG } from "../data/sampleOrg";

/** Least-privilege scopes — read only. No write scopes are ever requested. */
export const OAUTH_SCOPES = ["api", "refresh_token", "web"] as const;

export interface OrgDataProvider {
  readonly label: string;
  fetchSnapshot(): Promise<OrgSnapshot>;
}

/** Demo/offline provider backed by the bundled sample org. */
export class MockProvider implements OrgDataProvider {
  readonly label = "PLADS - SANDBOX TEST (sample)";
  async fetchSnapshot(): Promise<OrgSnapshot> {
    await new Promise((r) => setTimeout(r, 450)); // simulate scan latency
    return structuredClone(SAMPLE_ORG);
  }
}
