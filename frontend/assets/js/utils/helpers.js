const Helpers = {
  severityClass(sev) {
    return { CRITICAL:"badge-critical", HIGH:"badge-high", MEDIUM:"badge-medium", LOW:"badge-low", INFO:"badge-info" }[sev] || "badge-info";
  },
  severityBadge(sev) {
    return `<span class="badge ${this.severityClass(sev)}">${sev}</span>`;
  },
  fmtDate(iso) { return iso ? new Date(iso).toLocaleString() : "—"; },
  fmtDuration(seconds) { const m = Math.floor(seconds/60); const s = Math.round(seconds%60); return `${m}m ${s}s`; },
  truncate(str, n=80) { return str && str.length > n ? str.slice(0,n) + "…" : (str||""); },
  countSeverity(findings) {
    const c = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 };
    findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
    return c;
  },
  providerLabel(p) { return { aws:"AWS", azure:"Azure", gcp:"GCP" }[p] || (p||"").toUpperCase(); },
  statusBadge(status) {
    const map = {
      running:   ["badge-running",   "Running"],
      completed: ["badge-completed", "Completed"],
      error:     ["badge-failed",    "Error"],
      failed:    ["badge-failed",    "Failed"],
      queued:    ["badge-pending",   "Queued"],
      pending:   ["badge-pending",   "Pending"],
    };
    const [cls, label] = map[status] || ["badge-info", status];
    return `<span class="badge ${cls}">${label}</span>`;
  },
};
window.Helpers = Helpers;
