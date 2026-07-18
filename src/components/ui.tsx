import type { ReactNode } from "react";
import type { Severity, Status } from "../types";

export function Card({ title, sub, children, right }: { title?: string; sub?: string; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="card">
      {(title || right) && (
        <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start", marginBottom: sub ? 0 : 12 }}>
          <div>
            {title && <h3>{title}</h3>}
            {sub && <div className="card-sub">{sub}</div>}
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function Kpi({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: string }) {
  return (
    <div className="card kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={tone ? { color: tone } : undefined}>{value}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${severity.toLowerCase()}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: Status }) {
  if (status === "Passed") return <span className="badge pass">Passed</span>;
  if (status === "Failed") return <span className="badge fail">Failed</span>;
  return <span className="badge neutral">Not Evaluated</span>;
}

export function Bar({ value, color }: { value: number; color: string }) {
  return (
    <div className="bar-track">
      <div className="bar-fill" style={{ width: `${Math.max(2, Math.min(100, value))}%`, background: color }} />
    </div>
  );
}

function scoreColor(score: number): string {
  if (score >= 80) return "var(--pass)";
  if (score >= 55) return "var(--med)";
  return "var(--high)";
}

export function ScoreRing({ score, label = "posture score" }: { score: number; label?: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const color = scoreColor(score);
  return (
    <div className="score-ring">
      <svg width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={r} fill="none" stroke="var(--bg-elev2)" strokeWidth="12" />
        <circle
          cx="64" cy="64" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c - (pct / 100) * c}
          transform="rotate(-90 64 64)"
        />
      </svg>
      <div className="num">
        <div>
          <b style={{ color }}>{Math.round(score)}</b>
          <span>{label}</span>
        </div>
      </div>
    </div>
  );
}

export const SEV_COLOR: Record<Severity, string> = {
  High: "var(--high)",
  Medium: "var(--med)",
  Low: "var(--low)",
};
