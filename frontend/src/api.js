const BASE = import.meta.env.VITE_API_URL || "";

async function request(path, options) {
  let response;
  try {
    response = await fetch(`${BASE}${path}`, options);
  } catch {
    throw new Error("Cannot reach the API. Start the backend on port 8000.");
  }
  const contentType = response.headers.get("content-type") || "";
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    if (contentType.includes("application/json")) {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (body.detail) message = JSON.stringify(body.detail);
      if (Array.isArray(body.missing_columns) && body.missing_columns.length) {
        message += `: ${body.missing_columns.join(", ")}`;
      }
      if (Array.isArray(body.non_numeric_columns) && body.non_numeric_columns.length) {
        message += `: ${body.non_numeric_columns.join(", ")}`;
      }
    }
    throw new Error(message);
  }
  if (contentType.includes("application/json")) return response.json();
  return response;
}

export const api = {
  health: () => request("/api/health"),
  dashboard: () => request("/api/dashboard"),
  metrics: () => request("/api/model/metrics"),
  analyses: () => request("/api/analyses"),
  analysis: (id) => request(`/api/analyses/${id}`),
  flows: (id, page = 1, verdict = "", label = "") => {
    const params = new URLSearchParams({ page: String(page), page_size: "25" });
    if (verdict) params.set("verdict", verdict);
    if (label) params.set("label", label);
    return request(`/api/analyses/${id}/flows?${params.toString()}`);
  },
  alerts: () => request("/api/alerts?limit=200"),
  upload: (file) => {
    const body = new FormData();
    body.append("file", file);
    return request("/api/analyses", { method: "POST", body });
  },
  analyzeSample: () => request("/api/analyses/sample", { method: "POST" }),
  exportUrl: (id) => `${BASE}/api/analyses/${id}/export`,
  sampleUrl: () => `${BASE}/api/sample`,
};

export function formatInt(value) {
  return new Intl.NumberFormat().format(value ?? 0);
}

export function formatPct(ratio) {
  return `${((Number(ratio) || 0) * 100).toFixed(1)}%`;
}

export function formatScore(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  return Number(value).toFixed(3);
}

export function formatWhen(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
