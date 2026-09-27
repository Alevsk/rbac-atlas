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
    if (!window.Chart || !Chart.instances) return;
    var styles = getComputedStyle(root);
    var color = styles.getPropertyValue("--foreground").trim();
    var grid = styles.getPropertyValue("--chart-grid").trim();
    Object.values(Chart.instances).forEach(function (chart) {
      if (chart.options.plugins && chart.options.plugins.legend) {
        chart.options.plugins.legend.labels.color = color;
      }
      Object.values(chart.options.scales || {}).forEach(function (scale) {
        if (scale.ticks) scale.ticks.color = color;
        if (scale.grid && scale.grid.drawOnChartArea !== false) scale.grid.color = grid;
      });
      chart.data.datasets.forEach(function (dataset) {
        if (dataset.label === "Unique Projects") {
          dataset.borderColor = color;
          dataset.backgroundColor = color;
        }
      });
      chart.update("none");
    });
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
