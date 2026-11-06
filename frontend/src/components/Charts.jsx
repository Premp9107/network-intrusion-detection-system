import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const ATTACK_COLORS = ["#22d3ee", "#38bdf8", "#818cf8", "#f59e0b", "#fb7185", "#c084fc", "#34d399"];

const tooltipStyle = {
  background: "#0f172a",
  border: "1px solid #1e293b",
  borderRadius: 8,
  color: "#e2e8f0",
};

function colorFor(label, index) {
  if (label === "BENIGN") return "#34d399";
  return ATTACK_COLORS[index % ATTACK_COLORS.length];
}

export function AttackBar({ data }) {
  const rows = (data || []).map((item) => ({ name: item.label, count: item.count }));
  if (!rows.length) return null;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
        <CartesianGrid stroke="#1e293b" vertical={false} />
        <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} interval={0} />
        <YAxis stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,163,184,0.08)" }} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {rows.map((row, index) => (
            <Cell key={row.name} fill={colorFor(row.name, index)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ModelF1Chart({ models }) {
  const rows = Object.entries(models || {}).map(([name, metrics]) => ({
    name: name === "random_forest" ? "Random Forest" : "Logistic Regression",
    f1: metrics?.test?.f1_macro ?? 0,
    recall: metrics?.test?.recall_macro ?? 0,
  }));
  if (!rows.length) return null;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
        <CartesianGrid stroke="#1e293b" vertical={false} />
        <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} />
        <YAxis stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} domain={[0, 1]} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,163,184,0.08)" }} />
        <Bar dataKey="f1" name="Macro F1" fill="#22d3ee" radius={[4, 4, 0, 0]} />
        <Bar dataKey="recall" name="Macro recall" fill="#38bdf8" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function VerdictDonut({ benign, malicious }) {
  const data = [
    { name: "Benign", value: benign || 0, fill: "#34d399" },
    { name: "Malicious", value: malicious || 0, fill: "#fb7185" },
  ];
  if (!data[0].value && !data[1].value) return null;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={82} paddingAngle={3} stroke="none">
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.fill} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function BucketBar({ data }) {
  const rows = (data || []).map((item) => ({ name: item.range, count: item.count }));
  if (!rows.length) return null;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 8 }}>
        <CartesianGrid stroke="#1e293b" vertical={false} />
        <XAxis dataKey="name" stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} />
        <YAxis stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(148,163,184,0.08)" }} />
        <Bar dataKey="count" name="Flows" fill="#818cf8" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ImportanceBar({ features }) {
  const rows = (features || []).slice(0, 10).map((item) => ({ name: item.feature, value: item.value }));
  if (!rows.length) return null;
  return (
    <ResponsiveContainer width="100%" height={320}>
      <BarChart data={rows} layout="vertical" margin={{ top: 8, right: 16, left: 24, bottom: 8 }}>
        <CartesianGrid stroke="#1e293b" horizontal={false} />
        <XAxis type="number" stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 12 }} />
        <YAxis type="category" dataKey="name" width={210} stroke="#94a3b8" tick={{ fill: "#94a3b8", fontSize: 11 }} />
        <Tooltip contentStyle={tooltipStyle} />
        <Bar dataKey="value" name="Importance" fill="#22d3ee" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
