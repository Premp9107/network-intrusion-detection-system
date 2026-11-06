import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, formatInt, formatPct, formatScore, formatWhen } from "../api";
import { AttackBar, VerdictDonut } from "../components/Charts";
import { Banner, Empty, ErrorNote, Loading, Panel, SeverityBadge, StatCard, VerdictBadge } from "../components/ui";

export default function Results() {
  const params = useParams();
  const [analysis, setAnalysis] = useState(null);
  const [flows, setFlows] = useState(null);
  const [page, setPage] = useState(1);
  const [phase, setPhase] = useState("loading");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setPhase("loading");
    async function load() {
      try {
        let id = params.id;
        if (!id) {
          const listing = await api.analyses();
          id = listing.items[0]?.id;
        }
        if (!id) {
          if (active) {
            setAnalysis(null);
            setFlows(null);
            setPhase("empty");
          }
          return;
        }
        const [detail, flowPage] = await Promise.all([api.analysis(id), api.flows(id, page)]);
        if (!active) return;
        setAnalysis(detail);
        setFlows(flowPage);
        setPhase("ready");
      } catch (err) {
        if (active) {
          setError(err.message);
          setPhase("error");
        }
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [params.id, page]);

  if (error) return <ErrorNote message={error} />;
  if (phase === "empty") {
    return (
      <Empty>
        No detection results yet. <Link className="text-cyan-300" to="/upload">Upload a dataset</Link>.
      </Empty>
    );
  }
  if (phase !== "ready" || !analysis || !flows) return <Loading label="Loading results" />;

  const report = analysis.validation_report;
  const pages = Math.max(1, Math.ceil(flows.total / flows.page_size));

  return (
    <>
      <Banner tone={analysis.training_source_kind === "synthetic_demonstration" ? "warn" : "info"}>
        {analysis.original_filename} · {formatWhen(analysis.created_at)} · model {analysis.model_name.replaceAll("_", " ")}.{" "}
        {analysis.confidence_note} This view is an offline CSV result, not a live sensor feed.
      </Banner>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Flows" value={formatInt(analysis.total_flows)} hint={`${formatInt(report.imputed_cells)} missing cells imputed`} />
        <StatCard label="Benign" value={formatInt(analysis.benign_count)} tone="emerald" />
        <StatCard label="Malicious" value={formatInt(analysis.malicious_count)} tone="rose" />
        <StatCard label="Flagged share" value={formatPct(analysis.detection_rate)} tone="sky" hint={analysis.detection_rate_note} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Predicted categories">
          <AttackBar data={analysis.attack_distribution} />
        </Panel>
        <Panel
          title="Verdict mix"
          action={
            <a className="text-xs text-cyan-300" href={api.exportUrl(analysis.id)}>
              Export CSV
            </a>
          }
        >
          <VerdictDonut benign={analysis.benign_count} malicious={analysis.malicious_count} />
          <p className="text-sm text-slate-300">
            Mean estimated confidence {formatPct(analysis.mean_confidence)}.
            {analysis.label_agreement === null || analysis.label_agreement === undefined
              ? " This file has no Label column."
              : ` In-file label agreement is ${formatScore(analysis.label_agreement)}. That figure includes any rows the model may have trained on. Use Model Performance for the held-out scores.`}
          </p>
        </Panel>
      </div>
      <Panel title="Classified flows">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-400">
              <tr>
                <th className="pb-2 font-medium">Row</th>
                <th className="pb-2 font-medium">Verdict</th>
                <th className="pb-2 font-medium">Category</th>
                <th className="pb-2 font-medium">Severity</th>
                <th className="pb-2 font-medium">Confidence</th>
                <th className="pb-2 font-medium">File label</th>
              </tr>
            </thead>
            <tbody>
              {flows.items.map((flow) => (
                <tr key={flow.row_index} className="border-t border-line">
                  <td className="py-2 pr-3 font-mono text-slate-400">{flow.row_index}</td>
                  <td className="py-2 pr-3"><VerdictBadge verdict={flow.verdict} /></td>
                  <td className="py-2 pr-3">{flow.predicted_label}</td>
                  <td className="py-2 pr-3"><SeverityBadge severity={flow.severity} /></td>
                  <td className="py-2 pr-3 font-mono text-cyan-200">{formatPct(flow.confidence)}</td>
                  <td className="py-2 text-slate-400">{flow.ground_truth || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4 flex items-center justify-between text-sm text-slate-400">
          <span>Page {page} of {pages}</span>
          <div className="flex gap-2">
            <button className="rounded border border-line px-3 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
            <button className="rounded border border-line px-3 py-1 disabled:opacity-40" disabled={page >= pages} onClick={() => setPage((value) => value + 1)}>Next</button>
          </div>
        </div>
      </Panel>
    </>
  );
}
