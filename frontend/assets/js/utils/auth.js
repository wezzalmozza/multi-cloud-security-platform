/**
 * assets/js/utils/auth.js
 * Token storage, session helpers, and page guard.
 */

const Auth = {
  KEY: "mcpp_token",
  USER_KEY: "mcpp_user",

  _loginUrl() {
    const fromPages = window.location.pathname.includes("/pages/");
    return new URL(fromPages ? "../index.html" : "index.html", window.location.href).href;
  },

  save(token, user) {
    localStorage.setItem(this.KEY, token);
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
  },

  token()   { return localStorage.getItem(this.KEY); },
  user()    { const u = localStorage.getItem(this.USER_KEY); return u ? JSON.parse(u) : null; },
  isLoggedIn() { return !!this.token(); },

  expireSession() {
    localStorage.removeItem(this.KEY);
    localStorage.removeItem(this.USER_KEY);
    sessionStorage.removeItem("active_scan_id");
    sessionStorage.removeItem("scan_results");
  },

  logout() {
    this.expireSession();
    window.location.href = this._loginUrl();
  },

  /** Call at top of every protected page. Redirects to login if not authenticated. */
  guard() {
    if (!this.isLoggedIn()) {
      window.location.href = this._loginUrl();
      return false;
    }
    return true;
  },
};

window.Auth = Auth;
