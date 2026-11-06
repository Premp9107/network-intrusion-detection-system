import { useEffect, useState } from "react";
import { api, formatInt, formatScore } from "../api";
import { ImportanceBar } from "../components/Charts";
import { Banner, ErrorNote, Loading, Panel } from "../components/ui";

const NAMES = {
  random_forest: "Random Forest",
  logistic_regression: "Logistic Regression",
};

export default function Performance() {
  const [metrics, setMetrics] = useState(null);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    api.metrics()
      .then((data) => {
        if (!active) return;
        setMetrics(data);
        setSelected(data.selected_model);
      })
      .catch((err) => active && setError(err.message));
    return () => {
      active = false;
    };
  }, []);

  if (error) return <ErrorNote message={error} />;
  if (!metrics) return <Loading label="Loading model report" />;

  const model = metrics.models[selected];
  const labels = model.test.confusion_labels;
  const matrix = model.test.confusion_matrix;
  const report = model.test.classification_report;
  const maxCell = Math.max(...matrix.flat(), 1);

  return (
    <>
      <Banner tone="warn">
        Scores below are measured on the stratified held-out test split (test size {metrics.test_size}, random state {metrics.random_state}).
        Source: {metrics.training_source} ({metrics.training_source_kind.replaceAll("_", " ")}). {metrics.n_train} train rows, {metrics.n_test} test rows.
        These numbers are read from the training report. They are not typed in by hand.
      </Banner>
      <Panel title="Model comparison">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-400">
              <tr>
                <th className="pb-2 font-medium">Model</th>
                <th className="pb-2 font-medium">Accuracy</th>
                <th className="pb-2 font-medium">Precision</th>
                <th className="pb-2 font-medium">Recall</th>
                <th className="pb-2 font-medium">F1</th>
                <th className="pb-2 font-medium">Train F1</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(metrics.models).map(([name, item]) => (
                <tr key={name} className="border-t border-line">
                  <td className="py-2">
                    <button className={`text-left ${name === selected ? "text-cyan-200" : "text-slate-200"}`} onClick={() => setSelected(name)}>
                      {NAMES[name] || name}
                      {name === metrics.selected_model ? " · deployed" : ""}
                    </button>
                  </td>
                  <td className="py-2 font-mono">{formatScore(item.test.accuracy)}</td>
                  <td className="py-2 font-mono">{formatScore(item.test.precision_macro)}</td>
                  <td className="py-2 font-mono">{formatScore(item.test.recall_macro)}</td>
                  <td className="py-2 font-mono">{formatScore(item.test.f1_macro)}</td>
                  <td className="py-2 font-mono text-slate-400">{formatScore(item.train.f1_macro)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-slate-400">{metrics.selection_rule} Precision, recall, and F1 in this table are macro averages.</p>
      </Panel>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title={`${NAMES[selected] || selected} confusion matrix`}>
          <div className="overflow-x-auto">
            <table className="w-full border-separate border-spacing-1 text-center text-xs">
              <thead>
                <tr>
                  <th />
                  {labels.map((label) => (
                    <th key={label} className="px-1 font-medium text-slate-400">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {matrix.map((row, rowIndex) => (
                  <tr key={labels[rowIndex]}>
                    <th className="pr-2 text-left font-medium text-slate-400">{labels[rowIndex]}</th>
                    {row.map((value, columnIndex) => {
                      const intensity = value / maxCell;
                      return (
                        <td
                          key={`${labels[rowIndex]}-${labels[columnIndex]}`}
                          className="rounded px-2 py-2 font-mono text-slate-100"
                          style={{ background: `rgba(34, 211, 238, ${0.08 + intensity * 0.75})` }}
                        >
                          {formatInt(value)}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-slate-400">Rows are true labels. Columns are predicted labels.</p>
        </Panel>
        <Panel title="Classification report">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-400">
              <tr>
                <th className="pb-2 font-medium">Class</th>
                <th className="pb-2 font-medium">Precision</th>
                <th className="pb-2 font-medium">Recall</th>
                <th className="pb-2 font-medium">F1</th>
                <th className="pb-2 font-medium">Support</th>
              </tr>
            </thead>
            <tbody>
              {labels.map((label) => (
                <tr key={label} className="border-t border-line">
                  <td className="py-2">{label}</td>
                  <td className="py-2 font-mono">{formatScore(report[label]?.precision)}</td>
                  <td className="py-2 font-mono">{formatScore(report[label]?.recall)}</td>
                  <td className="py-2 font-mono">{formatScore(report[label]?.["f1-score"])}</td>
                  <td className="py-2 font-mono">{formatInt(report[label]?.support)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
      <Panel title={`Feature signal · ${metrics.feature_importance[selected].kind.replaceAll("_", " ")}`}>
        <ImportanceBar features={metrics.feature_importance[selected].features} />
        <p className="text-xs text-slate-400">
          {selected === "logistic_regression"
            ? "Logistic regression values are mean absolute coefficients, normalized to sum to 1."
            : "Random forest values are Gini importances from the trained model."}
        </p>
      </Panel>
    </>
  );
}
