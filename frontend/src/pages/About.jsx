import { useOutletContext } from "react-router-dom";
import { Panel } from "../components/ui";

export default function About() {
  const { health } = useOutletContext();
  return (
    <>
      <Panel title="Problem">
        <p className="text-sm leading-6 text-slate-300">
          Network intrusion records are too large to review flow by flow. Aegis NIDS trains scikit-learn classifiers
          on CIC-IDS2017-style flow features and scores uploaded CSV files as BENIGN or a malicious category. It is a
          university project and portfolio application, not a production sensor.
        </p>
      </Panel>
      <Panel title="What this system actually does">
        <p className="text-sm leading-6 text-slate-300">
          Detection is offline. An analyst uploads a flow CSV, the API validates it, and the saved preprocessing
          pipeline transforms those columns with the training-set medians and scaler. The deployed model then returns
          a class and an estimated probability. {health ? `The API currently has ${health.model_name.replaceAll("_", " ")} loaded, trained at ${health.trained_at}.` : "The model status is shown in the header once the API responds."} Aegis does not capture packets, mirror a switch port, or inspect live traffic.
        </p>
      </Panel>
      <Panel title="Architecture">
        <pre className="overflow-x-auto font-mono text-xs leading-6 text-cyan-100">{`Browser (React dashboard)
        |  HTTP /api
        v
FastAPI
  |- CSV validation (type, size, schema, missing values)
  |- Preprocessor saved with the model
  |- Random Forest or Logistic Regression
  |- SQLite history, alerts, and CSV export`}</pre>
      </Panel>
      <Panel title="Training data">
        <p className="text-sm leading-6 text-slate-300">
          The repository includes a 1,200-row synthetic demonstration set. Each class is sampled from its own feature
          distribution, with overlap, so the held-out metrics are measured rather than assumed. That file is not the
          CIC-IDS2017 corpus. Retrain with <span className="font-mono">python train.py --data your.csv</span> before
          treating scores on a real capture as meaningful.
        </p>
      </Panel>
      <Panel title="Limitations">
        <ul className="list-disc space-y-2 pl-5 text-sm leading-6 text-slate-300">
          <li>No real-time packet capture, flow export, or inline blocking.</li>
          <li>No user authentication. The API is intended for localhost.</li>
          <li>Uploads are limited to 10 MB and 25,000 rows.</li>
          <li>The default model only knows the classes present in its training file.</li>
          <li>Confidence is a predicted-class probability, not a calibrated certainty.</li>
        </ul>
      </Panel>
    </>
  );
}
