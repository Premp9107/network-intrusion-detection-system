import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, formatInt, formatPct, formatWhen } from "../api";
import { Empty, ErrorNote, Loading, Panel, SeverityBadge } from "../components/ui";

export default function History() {
  const [alerts, setAlerts] = useState(null);
  const [analyses, setAnalyses] = useState(null);
  const [severity, setSeverity] = useState("all");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([api.alerts(), api.analyses()])
      .then(([alertData, analysisData]) => {
        if (!active) return;
        setAlerts(alertData);
        setAnalyses(analysisData.items);
      })
      .catch((err) => active && setError(err.message));
    return () => {
      active = false;
    };
  }, []);

  if (error) return <ErrorNote message={error} />;
  if (!alerts || !analyses) return <Loading label="Loading history" />;

  const visible = alerts.items.filter((item) => severity === "all" || item.severity === severity);

  return (
    <>
      <Panel
        title="Malicious alerts"
        action={
          <select className="rounded-lg border border-line bg-[#0b1220] px-2 py-1 text-xs" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
        }
      >
        <p className="mb-3 text-xs text-slate-400">{alerts.confidence_note}</p>
        {visible.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-400">
                <tr>
                  <th className="pb-2 font-medium">When</th>
                  <th className="pb-2 font-medium">File</th>
                  <th className="pb-2 font-medium">Category</th>
                  <th className="pb-2 font-medium">Severity</th>
                  <th className="pb-2 font-medium">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((alert) => (
                  <tr key={`${alert.analysis_id}-${alert.row_index}`} className="border-t border-line">
                    <td className="py-2 pr-3 text-slate-300">{formatWhen(alert.created_at)}</td>
                    <td className="py-2 pr-3">
                      <Link className="text-cyan-200" to={`/results/${alert.analysis_id}`}>{alert.original_filename}</Link>
                    </td>
                    <td className="py-2 pr-3">{alert.predicted_label}</td>
                    <td className="py-2 pr-3"><SeverityBadge severity={alert.severity} /></td>
                    <td className="py-2 font-mono text-cyan-200">{formatPct(alert.confidence)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>No alerts match this filter.</Empty>
        )}
      </Panel>
      <Panel title="Analysis history">
        {analyses.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-400">
                <tr>
                  <th className="pb-2 font-medium">Run</th>
                  <th className="pb-2 font-medium">File</th>
                  <th className="pb-2 font-medium">Flows</th>
                  <th className="pb-2 font-medium">Malicious</th>
                  <th className="pb-2 font-medium">Flagged share</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((item) => (
                  <tr key={item.id} className="border-t border-line">
                    <td className="py-2 pr-3 text-slate-400">{formatWhen(item.created_at)}</td>
                    <td className="py-2 pr-3">
                      <Link className="text-cyan-200" to={`/results/${item.id}`}>{item.original_filename}</Link>
                    </td>
                    <td className="py-2 pr-3">{formatInt(item.total_flows)}</td>
                    <td className="py-2 pr-3 text-rose-300">{formatInt(item.malicious_count)}</td>
                    <td className="py-2 font-mono">{formatPct(item.detection_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>No analyses have been stored.</Empty>
        )}
      </Panel>
    </>
  );
}
