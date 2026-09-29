const Modal = {
  open(title, body) {
    const overlay = document.getElementById("modal-overlay");
    if (!overlay) return;
    document.getElementById("modal-title").textContent = title;
    document.getElementById("modal-body").innerHTML = body;
    overlay.classList.add("modal-open");
  },
  close() {
    const overlay = document.getElementById("modal-overlay");
    if (overlay) overlay.classList.remove("modal-open");
  },
};
document.addEventListener("keydown", e => { if (e.key === "Escape") Modal.close(); });
window.Modal = Modal;
