/**
 * sidebar.js — HTB-themed sidebar with SVG icons
 */

const Sidebar = {
  NAV: [
    { href: "dashboard.html",  icon: "dashboard",  label: "Dashboard"  },
    { href: "new-scan.html",   icon: "scan",       label: "New Scan"   },
    { href: "findings.html",   icon: "findings",   label: "Findings"   },
    { href: "history.html",    icon: "history",    label: "History"    },
    { href: "compliance.html", icon: "compliance", label: "Compliance" },
    { href: "profile.html",    icon: "profile",    label: "Profile"    },
  ],

  ICONS: {
    dashboard:  `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`,
    scan:       `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35M11 8v6M8 11h6"/></svg>`,
    findings:   `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/></svg>`,
    history:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.51"/><polyline points="12 7 12 12 15 14"/></svg>`,
    compliance: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`,
    profile:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  },

  render() {
    const el = document.getElementById("sidebar");
    if (!el) return;
    const user    = Auth.user() || {};
    const current = window.location.pathname.split("/").pop();
    const initials = (user.username || "?").slice(0, 2).toUpperCase();

    el.innerHTML = `
      <div class="sidebar-logo">
        <div class="logo-mark">
          <div class="logo-icon">⚡</div>
          <div>
            <div class="logo-text">MCPP</div>
            <div class="logo-sub">Pentest Platform</div>
          </div>
        </div>
      </div>

      <nav class="sidebar-nav">
        <div class="nav-section-label">Navigation</div>
        ${this.NAV.map(item => `
          <a href="${item.href}"
             class="nav-item ${current === item.href ? "nav-active" : ""}">
            <span class="nav-icon">${this.ICONS[item.icon] || ""}</span>
            <span>${item.label}</span>
          </a>`).join("")}
      </nav>

      <div class="sidebar-footer">
        <div class="user-card">
          <div class="user-info">
            <div class="user-avatar">${initials}</div>
            <div>
              <div class="user-name">${user.username || "—"}</div>
              <div class="user-role">${user.role || "analyst"}</div>
            </div>
          </div>
        </div>
        <button class="btn-logout" onclick="Auth.logout()">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Sign out
        </button>
      </div>`;
  },
};

document.addEventListener("DOMContentLoaded", () => Sidebar.render());
window.Sidebar = Sidebar;
