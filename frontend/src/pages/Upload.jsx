import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Banner, ErrorNote, Panel } from "../components/ui";

const MAX_BYTES = 10 * 1024 * 1024;

export default function Upload() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function choose(next) {
    setError("");
    if (!next) {
      setFile(null);
      return;
    }
    if (!next.name.toLowerCase().endsWith(".csv")) {
      setFile(null);
      setError("Choose a .csv file.");
      return;
    }
    if (next.size > MAX_BYTES) {
      setFile(null);
      setError("File exceeds the 10 MB limit.");
      return;
    }
    setFile(next);
  }

  async function submit(event) {
    event.preventDefault();
    if (!file) {
      setError("Choose a CSV file first.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const analysis = await api.upload(file);
      navigate(`/results/${analysis.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function useSample() {
    setBusy(true);
    setError("");
    try {
      const analysis = await api.analyzeSample();
      navigate(`/results/${analysis.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Banner>
        Upload a flow record CSV. Files are parsed in memory and are never executed. The server rejects non-CSV
        extensions, files over 10 MB, and more than 25,000 rows.
      </Banner>
      <Panel title="Analyze a capture file">
        <form onSubmit={submit} className="space-y-4">
          <label className="flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-cyan-400/40 bg-[#0b1220] px-6 py-10 text-center">
            <span className="text-sm text-slate-200">{file ? file.name : "Select a CIC-IDS2017-compatible CSV"}</span>
            <span className="mt-1 text-xs text-slate-400">{file ? `${(file.size / 1024).toFixed(1)} KB` : "Comma-separated UTF-8, 10 MB maximum"}</span>
            <input
              className="sr-only"
              type="file"
              accept=".csv,text/csv"
              onChange={(event) => choose(event.target.files?.[0])}
            />
          </label>
          <ErrorNote message={error} />
          <div className="flex flex-wrap gap-3">
            <button type="submit" disabled={busy} className="rounded-lg bg-cyan-400 px-4 py-2 text-sm font-medium text-slate-950 disabled:opacity-60">
              {busy ? "Classifying…" : "Classify flows"}
            </button>
            <button type="button" disabled={busy} onClick={useSample} className="rounded-lg border border-line px-4 py-2 text-sm text-slate-200">
              Analyze bundled sample
            </button>
            <a className="rounded-lg border border-line px-4 py-2 text-sm text-cyan-200" href={api.sampleUrl()}>
              Download sample CSV
            </a>
          </div>
        </form>
      </Panel>
      <Panel title="Required columns">
        <p className="text-sm leading-6 text-slate-300">
          The file must include the 27 CIC-IDS2017 feature names used by the training pipeline. A Label column is
          optional. When it is present, the results page shows in-file agreement and does not treat that number as the
          held-out test score. Extra columns are ignored. A Timestamp column is displayed when it exists.
        </p>
      </Panel>
    </>
  );
}
