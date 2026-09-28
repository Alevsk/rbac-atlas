(function () {
  var root = document.documentElement;
  var button = document.querySelector(".theme-toggle");
  if (!button) return;

  function updateButton() {
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    var label = "Switch to " + next + " mode";
    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
  }

  function updateCharts() {
    if (window.RBACCharts) window.RBACCharts.refreshAll();
  }

  updateButton();
  button.addEventListener("click", function () {
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try {
      localStorage.setItem("rbac-atlas-theme", next);
    } catch (_) {
      /* Storage may be disabled. */
    }
    updateButton();
    updateCharts();
  });

  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function (event) {
    try {
      if (localStorage.getItem("rbac-atlas-theme")) return;
    } catch (_) {
      /* Keep system preference. */
    }
    root.setAttribute("data-theme", event.matches ? "dark" : "light");
    updateButton();
    updateCharts();
  });
})();
