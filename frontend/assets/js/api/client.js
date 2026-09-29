/**
 * assets/js/api/client.js
 * Single place for every API call.
 * Import this from page scripts — never call fetch() directly in page code.
 */

const BASE = "http://127.0.0.1:8000/api/v1";

function _headers() {
  const token = localStorage.getItem("mcpp_token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function _request(method, path, body = null, { auth = true } = {}) {
  const opts = {
    method,
    headers: auth
      ? _headers()
      : { "Content-Type": "application/json" },
  };

  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(BASE + path, opts);

  if (res.status === 401 && auth) {
    if (window.Auth && typeof Auth.expireSession === "function") {
      Auth.expireSession();
    }
    throw new Error("Session expired. Please sign in again.");
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }

  return res.status === 204 ? null : res.json();
}

async function fetchAiReport(scanId) {
  const opts = { method: "POST", headers: _headers() };
  const response = await fetch(`${BASE}/scans/${scanId}/report/ai`, opts);
  if (!response.ok) {
    throw new Error(`AI report failed: ${response.statusText}`);
  }
  return response.json();
}

const API = {
  // ── Auth ────────────────────────────────────────────────────────────────
  login: (username, password) =>
    _request(
      "POST",
      "/auth/login",
      { username, password },
      { auth: false }
    ),

  createUser: (username, password) =>
    _request(
      "POST",
      "/auth/create-user",
      { username, password },
      { auth: false }
    ),

  // ── Modules ─────────────────────────────────────────────────────────────
  getModules: () => _request("GET", "/modules"),

  // ── Scans ───────────────────────────────────────────────────────────────
  listScans: () => _request("GET", "/scans"),
  preflightAuth: (payload) => _request("POST", "/scans/preflight-auth", payload),
  startScan: (payload) => _request("POST", "/scans", payload),
  getScan: (id) => _request("GET", `/scans/${id}`),

  getFindings: (id, filters = {}) => {
    const q = new URLSearchParams(filters).toString();
    return _request(
      "GET",
      `/scans/${id}/findings${q ? "?" + q : ""}`
    );
  },

  // ── AI Report ───────────────────────────────────────────────────────────
  fetchAiReport,

  // ── PDF Report ──────────────────────────────────────────────────────────
  async fetchPdfReport(scanId) {
    const opts = { method: "POST", headers: _headers() };
    const response = await fetch(`${BASE}/scans/${scanId}/report/pdf`, opts);
    if (response.status === 401) {
      if (window.Auth && typeof Auth.expireSession === "function") Auth.expireSession();
      throw new Error("Session expired. Please sign in again.");
    }
    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(err.detail || "PDF generation failed");
    }
    return response.blob();
  },

  // ── WebSocket: live progress ─────────────────────────────────────────────
  streamScan(scanId, onMessage, onClose) {
    const wsBase = BASE.replace(/^http/, "ws");
    const ws = new WebSocket(`${wsBase}/scans/${scanId}/stream`);

    ws.onmessage = (e) => onMessage(JSON.parse(e.data));
    ws.onclose = onClose || (() => {});
    ws.onerror = (e) => console.error("WS error", e);

    return ws;
  },
};

window.API = API;