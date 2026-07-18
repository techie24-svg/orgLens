import { useState } from "react";
import type { Store } from "../store";
import { Card } from "./ui";
import { OAUTH_SCOPES } from "../lib/salesforce";

export function Connections({ store, onScanned }: { store: Store; onScanned: () => void }) {
  const [host, setHost] = useState("https://login.salesforce.com");
  const [myDomain, setMyDomain] = useState("");

  const resolvedHost = host === "custom" ? myDomain.trim() : host;
  const canConnect = host !== "custom" || myDomain.trim().length > 0;

  const connectLive = () => {
    if (!canConnect) return;
    store.connectLive(resolvedHost);
  };

  const runDemo = async () => {
    await store.runDemo();
    onScanned();
  };

  return (
    <div className="grid cols-2" style={{ alignItems: "start" }}>
      <Card title="Connect a Salesforce org" sub="Agentless, read-only — authorize via OAuth like Workbench.">
        {store.error && (
          <div className="banner error" style={{ marginBottom: 12 }}>
            {store.error}
          </div>
        )}
        <label className="field">
          <span className="lbl">Login host</span>
          <select className="select" value={host} onChange={(e) => setHost(e.target.value)}>
            <option value="https://login.salesforce.com">Production / Developer (login.salesforce.com)</option>
            <option value="https://test.salesforce.com">Sandbox (test.salesforce.com)</option>
            <option value="custom">Custom My Domain…</option>
          </select>
        </label>
        {host === "custom" && (
          <label className="field">
            <span className="lbl">My Domain</span>
            <input
              className="select"
              placeholder="acme.my.salesforce.com"
              value={myDomain}
              onChange={(e) => setMyDomain(e.target.value)}
            />
          </label>
        )}
        <label className="field">
          <span className="lbl">OAuth scopes requested</span>
          <div className="wrap">
            {OAUTH_SCOPES.map((s) => <span key={s} className="tag">{s}</span>)}
            <span className="tag" style={{ color: "var(--pass)" }}>no write scopes</span>
          </div>
        </label>

        <div className="divider" />
        <div className="row" style={{ justifyContent: "space-between", gap: 12 }}>
          <button className="btn" onClick={runDemo} disabled={store.scanning}>
            {store.scanning && store.mode === "demo" ? "Scanning…" : "Try demo (sample org)"}
          </button>
          <button className="btn primary" onClick={connectLive} disabled={!canConnect || store.scanning}>
            Connect real org via OAuth
          </button>
        </div>
        <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>
          Connecting redirects you to Salesforce to authorize a read-only Connected App, then runs a live scan.
          Requires the app's OAuth credentials to be configured (see README).
        </div>
        {store.deployedCommit && (
          <div className="muted mono" style={{ fontSize: 11, marginTop: 8 }}>
            build {store.deployedCommit}
          </div>
        )}
      </Card>

      <Card title="Least-privilege access" sub="The scanner is assigned this read-only permission set — it can never modify the org.">
        <div className="wrap">
          {["ViewHealthCheck", "ViewSetup", "ViewAllUsers", "ViewAllProfiles", "ViewRoles", "ViewEventLogFiles", "ViewDataLeakageEvents", "ViewAllCustomSettings", "ApiEnabled"].map((p) => (
            <span key={p} className="tag mono">{p}</span>
          ))}
        </div>
        <div className="divider" />
        <div className="kv"><span className="k">Excluded</span><span style={{ color: "var(--pass)" }}>ModifyAllData, ModifyMetadata (never requested)</span></div>
        <div className="kv"><span className="k">Interactive</span><span>OAuth 2.0 web-server flow + PKCE</span></div>
        <div className="kv"><span className="k">Token storage</span><span>Encrypted httpOnly cookie (server-side)</span></div>
        <div className="kv"><span className="k">Metadata source</span><span>Health Check · Tooling · SOQL</span></div>
      </Card>

      {store.connected && store.snapshot && (
        <Card title={store.mode === "live" ? "Connected org (live)" : "Sample org (demo)"}>
          <div className="kv"><span className="k">Alias</span><span>{store.snapshot.org.alias}</span></div>
          <div className="kv"><span className="k">Domain</span><span className="mono">{store.instanceHost ?? store.snapshot.org.orgDomain}</span></div>
          <div className="kv"><span className="k">Type</span><span>{store.snapshot.org.instanceType}</span></div>
          <div className="kv"><span className="k">Active users</span><span>{store.snapshot.totalActiveUsers}</span></div>
          <div className="kv"><span className="k">Health Check score</span><span>{store.snapshot.healthCheckScore}</span></div>
          <div className="kv"><span className="k">Checks run</span><span>{store.findings.length}</span></div>
          {store.mode === "live" && store.snapshot._diagnostics && store.snapshot._diagnostics.length > 0 && (
            <>
              <div className="divider" />
              <div className="lbl" style={{ marginBottom: 6 }}>API calls that failed ({store.snapshot._diagnostics.length})</div>
              <div className="banner error" style={{ display: "block", whiteSpace: "pre-wrap", fontSize: 12, lineHeight: 1.5 }}>
                {store.snapshot._diagnostics.join("\n")}
              </div>
            </>
          )}
          {store.mode === "live" && (
            <>
              <div className="divider" />
              <button className="btn" onClick={store.disconnect}>Disconnect</button>
            </>
          )}
        </Card>
      )}
    </div>
  );
}
