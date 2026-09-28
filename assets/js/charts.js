(function () {
  function palette() {
    var styles = getComputedStyle(document.documentElement);
    function read(name, fallback) {
      return styles.getPropertyValue(name).trim() || fallback;
    }
    return {
      foreground: read("--foreground", "#172338"),
      muted: read("--muted", "#617086"),
      surface: read("--surface", "#ffffff"),
      border: read("--border", "#e1e8f1"),
      grid: read("--chart-grid", "rgba(36, 54, 87, 0.09)"),
      critical: read("--critical", "#b9344c"),
      high: read("--high", "#b95f29"),
      medium: read("--medium", "#906a0f"),
      low: read("--low", "#087b72"),
    };
  }

  function dataset(label, data, colorKey, extra) {
    var colors = palette();
    var color = colors[colorKey] || colorKey;
    return Object.assign(
      {
        label: label,
        data: data,
        rbacColorKey: colorKey,
        borderColor: color,
        backgroundColor: color,
        borderWidth: 2.5,
        borderCapStyle: "round",
        borderJoinStyle: "round",
        tension: 0.35,
        pointRadius: 0,
        pointHitRadius: 12,
        pointHoverRadius: 5,
        pointHoverBackgroundColor: color,
        pointHoverBorderColor: colors.surface,
        pointHoverBorderWidth: 2,
        fill: false,
      },
      extra || {},
    );
  }

  function axisTicks(colors, limit) {
    return {
      color: colors.muted,
      padding: 10,
      maxTicksLimit: limit,
      font: { family: "Inter, sans-serif", size: 11, weight: 500 },
    };
  }

  function lineOptions(settings) {
    settings = settings || {};
    var colors = palette();
    var options = {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { mode: "index", intersect: false },
      layout: { padding: { top: 8, right: 6 } },
      plugins: {
        legend: {
          display: !settings.hideLegend,
          position: "bottom",
          align: "start",
          labels: {
            color: colors.muted,
            usePointStyle: true,
            pointStyle: "circle",
            boxWidth: 8,
            boxHeight: 8,
            padding: 18,
            font: { family: "Inter, sans-serif", size: 11, weight: 600 },
          },
        },
        tooltip: {
          backgroundColor: colors.surface,
          borderColor: colors.border,
          borderWidth: 1,
          titleColor: colors.foreground,
          bodyColor: colors.muted,
          titleFont: { family: "Inter, sans-serif", size: 12, weight: 700 },
          bodyFont: { family: "Inter, sans-serif", size: 12 },
          padding: 12,
          cornerRadius: 10,
          usePointStyle: true,
          boxPadding: 5,
          callbacks: {
            label: function (context) {
              return context.dataset.label + ": " + Number(context.parsed.y).toLocaleString();
            },
          },
        },
      },
      scales: {
        x: {
          border: { display: false },
          grid: { display: false },
          ticks: Object.assign(axisTicks(colors, settings.xTickLimit || 6), {
            maxRotation: 0,
            autoSkip: true,
          }),
        },
        y: {
          beginAtZero: true,
          border: { display: false },
          grid: { color: colors.grid, drawTicks: false },
          ticks: Object.assign(axisTicks(colors, 5), {
            callback: function (value) {
              return Number(value).toLocaleString();
            },
          }),
        },
      },
    };

    if (settings.tooltipTitle) {
      options.plugins.tooltip.callbacks.title = settings.tooltipTitle;
    }
    if (settings.secondaryAxis) {
      options.scales.y1 = {
        position: "right",
        beginAtZero: true,
        border: { display: false },
        grid: { display: false },
        ticks: Object.assign(axisTicks(colors, 5), {
          callback: function (value) {
            return Number(value).toLocaleString();
          },
        }),
      };
    }
    return options;
  }

  function sparklineOptions() {
    var options = lineOptions({ hideLegend: true });
    options.layout.padding = { top: 8, right: 4, bottom: 2, left: 4 };
    options.scales = { x: { display: false }, y: { display: false } };
    return options;
  }

  function refreshAll() {
    if (!window.Chart || !Chart.instances) return;
    var colors = palette();
    Object.values(Chart.instances).forEach(function (chart) {
      chart.data.datasets.forEach(function (series) {
        if (!series.rbacColorKey) return;
        var color = colors[series.rbacColorKey] || series.rbacColorKey;
        series.borderColor = color;
        series.backgroundColor = color;
        series.pointHoverBackgroundColor = color;
        series.pointHoverBorderColor = colors.surface;
      });
      var plugins = chart.options.plugins || {};
      if (plugins.legend && plugins.legend.labels) plugins.legend.labels.color = colors.muted;
      if (plugins.tooltip) {
        plugins.tooltip.backgroundColor = colors.surface;
        plugins.tooltip.borderColor = colors.border;
        plugins.tooltip.titleColor = colors.foreground;
        plugins.tooltip.bodyColor = colors.muted;
      }
      Object.values(chart.options.scales || {}).forEach(function (scale) {
        if (scale.ticks) scale.ticks.color = colors.muted;
        if (scale.grid && scale.grid.display !== false) scale.grid.color = colors.grid;
      });
      chart.update("none");
    });
  }

  window.RBACCharts = {
    dataset: dataset,
    lineOptions: lineOptions,
    sparklineOptions: sparklineOptions,
    refreshAll: refreshAll,
  };
})();
