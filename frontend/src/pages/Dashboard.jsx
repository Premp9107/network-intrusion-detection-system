import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, formatInt, formatPct, formatScore, formatWhen } from "../api";
import { AttackBar, ModelF1Chart } from "../components/Charts";
import { Banner, Empty, ErrorNote, Loading, Panel, SeverityBadge, StatCard } from "../components/ui";

export default function Dashboard() {
  const [dashboard, setDashboard] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([api.dashboard(), api.metrics()])
      .then(([dash, model]) => {
        if (!active) return;
        setDashboard(dash);
        setMetrics(model);
      })
      .catch((err) => active && setError(err.message));
    return () => {
      active = false;
    };
  }, []);

  if (error) return <ErrorNote message={error} />;
  if (!dashboard || !metrics) return <Loading label="Loading dashboard" />;

  return (
    <>
      <Banner tone="warn">
        Totals come from CSV analyses stored in the local database. Detection rate is the share of flows flagged
        malicious, not model recall. {metrics.training_source_kind === "synthetic_demonstration" && "The active model was trained on synthetic demonstration data."}
      </Banner>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Analyzed flows" value={formatInt(dashboard.total_flows)} hint={`${formatInt(dashboard.analysis_count)} saved analyses`} />
        <StatCard label="Benign traffic" value={formatInt(dashboard.benign_count)} tone="emerald" hint="Predicted class BENIGN" />
        <StatCard label="Malicious traffic" value={formatInt(dashboard.malicious_count)} tone="rose" hint="Any predicted class other than BENIGN" />
        <StatCard label="Detection rate" value={formatPct(dashboard.detection_rate)} tone="sky" hint={dashboard.detection_rate_note} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Attack distribution" action={<Link className="text-xs text-cyan-300" to="/results">View results</Link>}>
          {dashboard.attack_distribution.length ? <AttackBar data={dashboard.attack_distribution} /> : <Empty>Upload a CSV to populate this chart.</Empty>}
        </Panel>
        <Panel title="Held-out model scores" action={<Link className="text-xs text-cyan-300" to="/performance">Full report</Link>}>
          <ModelF1Chart models={metrics.models} />
          <p className="mt-2 text-xs text-slate-400">
            Selected model: {metrics.selected_model.replaceAll("_", " ")}. Macro F1 {formatScore(metrics.models[metrics.selected_model].test.f1_macro)} on {formatInt(metrics.n_test)} test rows.
          </p>
        </Panel>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Recent alerts">
          {dashboard.recent_alerts.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-400">
                  <tr>
                    <th className="pb-2 font-medium">When</th>
                    <th className="pb-2 font-medium">Category</th>
                    <th className="pb-2 font-medium">Severity</th>
                    <th className="pb-2 font-medium">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {dashboard.recent_alerts.map((alert) => (
                    <tr key={`${alert.analysis_id}-${alert.row_index}-${alert.created_at}`} className="border-t border-line">
                      <td className="py-2 pr-3 text-slate-300">{formatWhen(alert.created_at)}</td>
                      <td className="py-2 pr-3">{alert.predicted_label}</td>
                      <td className="py-2 pr-3"><SeverityBadge severity={alert.severity} /></td>
                      <td className="py-2 font-mono text-cyan-200">{formatPct(alert.confidence)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No malicious flows have been stored yet.</Empty>
          )}
        </Panel>
        <Panel title="Traffic analysis history" action={<Link className="text-xs text-cyan-300" to="/alerts">Alert history</Link>}>
          {dashboard.recent_analyses.length ? (
            <div className="space-y-2">
              {dashboard.recent_analyses.map((item) => (
                <Link key={item.id} to={`/results/${item.id}`} className="flex items-center justify-between rounded-lg border border-line px-3 py-2 hover:border-cyan-400/40">
                  <span>
                    <span className="block text-sm">{item.original_filename}</span>
                    <span className="text-xs text-slate-400">{formatWhen(item.created_at)}</span>
                  </span>
                  <span className="text-right text-xs text-slate-300">
                    {formatInt(item.total_flows)} flows
                    <span className="block text-rose-300">{formatPct(item.detection_rate)} flagged</span>
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            <Empty>
              No analyses yet. <Link className="text-cyan-300" to="/upload">Upload a dataset</Link>.
            </Empty>
          )}
        </Panel>
      </div>
    </>
  );
}
