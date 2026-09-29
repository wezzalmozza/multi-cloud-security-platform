const Toast = {
  _el: null,
  _timer: null,
  _get() {
    if (!this._el) {
      this._el = document.createElement("div");
      this._el.className = "toast";
      document.body.appendChild(this._el);
    }
    return this._el;
  },
  show(msg, type="info", duration=3500) {
    const el = this._get();
    if (this._timer) { clearTimeout(this._timer); el.classList.remove("toast-visible"); }
    setTimeout(() => {
      el.className = `toast toast-${type}`;
      const icons = { success:"✓", error:"✕", info:"ℹ" };
      el.innerHTML = `<span>${icons[type]||""}</span><span>${msg}</span>`;
      requestAnimationFrame(() => el.classList.add("toast-visible"));
      this._timer = setTimeout(() => el.classList.remove("toast-visible"), duration);
    }, 50);
  },
  success(msg) { this.show(msg, "success"); },
  error(msg)   { this.show(msg, "error", 5000); },
  info(msg)    { this.show(msg, "info"); },
};
window.Toast = Toast;
