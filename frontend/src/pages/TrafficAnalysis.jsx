import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, formatInt, formatPct, formatWhen } from "../api";
import { BucketBar, VerdictDonut } from "../components/Charts";
import { Banner, Empty, ErrorNote, Loading, Panel, VerdictBadge } from "../components/ui";

export default function TrafficAnalysis() {
  const [analyses, setAnalyses] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [flows, setFlows] = useState(null);
  const [verdict, setVerdict] = useState("");
  const [page, setPage] = useState(1);
  const [active, setActive] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    api.analyses()
      .then((data) => {
        if (!live) return;
        setAnalyses(data.items);
        setLoaded(true);
        if (data.items[0]) setSelected(String(data.items[0].id));
      })
      .catch((err) => live && setError(err.message));
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!selected) return undefined;
    let live = true;
    Promise.all([api.analysis(selected), api.flows(selected, page, verdict)])
      .then(([detail, flowPage]) => {
        if (!live) return;
        setAnalysis(detail);
        setFlows(flowPage);
        setActive(null);
      })
      .catch((err) => live && setError(err.message));
    return () => {
      live = false;
    };
  }, [selected, page, verdict]);

  if (error) return <ErrorNote message={error} />;
  if (!loaded) return <Loading label="Loading analyses" />;
  if (!analyses.length) {
    return (
      <Empty>
        Nothing to inspect yet. <Link className="text-cyan-300" to="/upload">Run an analysis</Link>.
      </Empty>
    );
  }
  if (!analysis || !flows) return <Loading label="Loading traffic" />;

  const pages = Math.max(1, Math.ceil(flows.total / flows.page_size));

  return (
    <>
      <Banner>
        Inspect stored flow decisions. Confidence values are model estimates. Aegis does not watch a network interface.
      </Banner>
      <Panel title="Saved analysis">
        <div className="flex flex-wrap gap-3">
          <select
            className="rounded-lg border border-line bg-[#0b1220] px-3 py-2 text-sm"
            value={selected}
            onChange={(event) => {
              setPage(1);
              setSelected(event.target.value);
            }}
          >
            {analyses.map((item) => (
              <option key={item.id} value={item.id}>
                #{item.id} {item.original_filename} · {formatWhen(item.created_at)}
              </option>
            ))}
          </select>
          <select
            className="rounded-lg border border-line bg-[#0b1220] px-3 py-2 text-sm"
            value={verdict}
            onChange={(event) => {
              setPage(1);
              setVerdict(event.target.value);
            }}
          >
            <option value="">All verdicts</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="BENIGN">Benign</option>
          </select>
        </div>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Verdict mix">
          <VerdictDonut benign={analysis.benign_count} malicious={analysis.malicious_count} />
        </Panel>
        <Panel title="Confidence estimates">
          <BucketBar data={analysis.confidence_buckets} />
          <p className="text-xs text-slate-400">{analysis.confidence_note}</p>
        </Panel>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px]">
        <Panel title={`Flows (${formatInt(flows.total)})`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-slate-400">
                <tr>
                  <th className="pb-2 font-medium">Row</th>
                  <th className="pb-2 font-medium">Verdict</th>
                  <th className="pb-2 font-medium">Category</th>
                  <th className="pb-2 font-medium">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {flows.items.map((flow) => (
                  <tr
                    key={flow.row_index}
                    role="button"
                    tabIndex={0}
                    className="cursor-pointer border-t border-line hover:bg-white/5"
                    onClick={() => setActive(flow)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setActive(flow);
                      }
                    }}
                  >
                    <td className="py-2 font-mono text-slate-400">{flow.row_index}</td>
                    <td className="py-2"><VerdictBadge verdict={flow.verdict} /></td>
                    <td className="py-2">{flow.predicted_label}</td>
                    <td className="py-2 font-mono text-cyan-200">{formatPct(flow.confidence)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex justify-end gap-2 text-sm">
            <button className="rounded border border-line px-3 py-1 disabled:opacity-40" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
            <button className="rounded border border-line px-3 py-1 disabled:opacity-40" disabled={page >= pages} onClick={() => setPage((value) => value + 1)}>Next</button>
          </div>
        </Panel>
        <Panel title="Estimate">
          {active ? (
            <div className="space-y-2 text-sm leading-6 text-slate-300">
              <p>
                Row {active.row_index} was classified as <strong className="text-slate-100">{active.predicted_label}</strong> with an estimated probability of {formatPct(active.confidence)}.
              </p>
              <p>{flows.confidence_note}</p>
              <p>The malicious verdict means the predicted category is not BENIGN.</p>
              {active.ground_truth && <p>Label stored in the file: {active.ground_truth}.</p>}
            </div>
          ) : (
            <Empty>Select a row to read the model estimate.</Empty>
          )}
        </Panel>
      </div>
    </>
  );
}
