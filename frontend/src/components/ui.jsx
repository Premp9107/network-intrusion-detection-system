import { formatInt, formatPct, formatScore } from "../api";

export { formatInt, formatPct, formatScore };

export function Panel({ title, action, children, className = "" }) {
  return (
    <section className={`rounded-xl border border-line bg-panel ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-sm font-medium text-slate-100">{title}</h2>
          {action}
        </div>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint, tone = "cyan" }) {
  const tones = {
    cyan: "text-cyan-300",
    emerald: "text-emerald-300",
    rose: "text-rose-300",
    sky: "text-sky-300",
  };
  return (
    <article className="rounded-xl border border-line bg-panel px-4 py-4">
      <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
      <p className={`mt-2 font-mono text-2xl font-medium ${tones[tone] || tones.cyan}`}>{value}</p>
      {hint && <p className="mt-2 text-xs leading-5 text-slate-400">{hint}</p>}
    </article>
  );
}

export function SeverityBadge({ severity }) {
  const styles = {
    critical: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
    high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
    medium: "bg-amber-500/15 text-amber-200 ring-amber-500/30",
    info: "bg-slate-500/15 text-slate-300 ring-slate-500/30",
  };
  return (
    <span className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs ring-1 ${styles[severity] || styles.medium}`}>
      {severity || "medium"}
    </span>
  );
}

export function VerdictBadge({ verdict }) {
  const malicious = verdict === "MALICIOUS";
  return (
    <span
      className={`inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs ring-1 ${
        malicious ? "bg-rose-500/15 text-rose-300 ring-rose-500/30" : "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30"
      }`}
    >
      {verdict}
    </span>
  );
}

export function Banner({ children, tone = "info" }) {
  const tones = {
    info: "border-sky-500/30 bg-sky-500/10 text-sky-100",
    warn: "border-amber-500/30 bg-amber-500/10 text-amber-100",
  };
  return <div className={`rounded-lg border px-3 py-2 text-sm leading-6 ${tones[tone] || tones.info}`}>{children}</div>;
}

export function Loading({ label = "Loading" }) {
  return <p className="text-sm text-slate-400">{label}…</p>;
}

export function ErrorNote({ message }) {
  if (!message) return null;
  return <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-100">{message}</div>;
}

export function Empty({ children }) {
  return <p className="text-sm text-slate-400">{children}</p>;
}
