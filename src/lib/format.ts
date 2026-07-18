export function pct(n: number): string {
  return `${Math.round(n)}%`;
}

export function todayLabel(): string {
  return new Date().toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export const SEVERITY_ORDER: Record<string, number> = { High: 0, Medium: 1, Low: 2 };
