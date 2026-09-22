/**
 * TRINETRA AI - Advanced Analytics
 * Chart.js visualizations driven by /api/analytics/overview.
 */
(function () {
  "use strict";

  const cfg = window.__TRINETRA_ANALYTICS__ || {};
  const state = {
    range: "30d",
    type: "all",
    verdict: "all",
    start: "",
    end: "",
  };

  const charts = {};

  const CHART_TICK = { color: "#6f81a0", font: { family: "JetBrains Mono", size: 10 } };
  const CHART_LEGEND = {
    labels: {
      color: "#aebdd4",
      font: { family: "Rajdhani", size: 12, weight: "600" },
      usePointStyle: true,
      boxWidth: 8,
    },
  };
  const CHART_TOOLTIP = {
    backgroundColor: "#0d1a2f",
    borderColor: "rgba(0,229,255,0.2)",
    borderWidth: 1,
    titleColor: "#eaf4ff",
    bodyColor: "#aebdd4",
    padding: 10,
    titleFont: { family: "Rajdhani" },
    bodyFont: { family: "Rajdhani" },
  };
  const GRID = { color: "rgba(255,255,255,0.04)" };
  const TYPE_COLORS = ["#00e5ff", "#7b61ff", "#ffb020", "#ff3860", "#00ffa3", "#5b8cff", "#c084fc"];

  function queryString() {
    const params = new URLSearchParams();
    params.set("range", state.range);
    params.set("type", state.type);
    params.set("verdict", state.verdict);
    if (state.range === "custom") {
      if (state.start) params.set("start", state.start);
      if (state.end) params.set("end", state.end);
    }
    return params.toString();
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function setText(selector, value) {
    document.querySelectorAll(selector).forEach(function (el) {
      el.textContent = value;
    });
  }

  function emptyData(labels) {
    return labels.map(function () {
      return 0;
    });
  }

  function upsertChart(id, config) {
    const canvas = document.getElementById(id);
    if (!canvas || !window.Chart) return;
    if (charts[id]) {
      const sameCount = charts[id].data.datasets.length === config.data.datasets.length;
      const sameLabels = (charts[id].data.labels || []).length === (config.data.labels || []).length;
      if (!sameCount || !sameLabels) {
        charts[id].destroy();
        charts[id] = new window.Chart(canvas.getContext("2d"), config);
        return;
      }
      charts[id].data.labels = config.data.labels;
      charts[id].data.datasets.forEach(function (ds, i) {
        const next = config.data.datasets[i];
        if (!next) return;
        ds.data = next.data;
        if (next.label) ds.label = next.label;
        if (next.backgroundColor) ds.backgroundColor = next.backgroundColor;
        if (next.borderColor) ds.borderColor = next.borderColor;
      });
      charts[id].update();
      return;
    }
    charts[id] = new window.Chart(canvas.getContext("2d"), config);
  }

  function lineGradient(canvas, rgbaFrom) {
    const ctx = canvas.getContext("2d");
    const gradient = ctx.createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0, rgbaFrom);
    gradient.addColorStop(1, "rgba(0,0,0,0)");
    return gradient;
  }

  function renderSummary(payload) {
    const s = payload.summary || {};
    setText('[data-stat="total"]', String(s.total || 0));
    setText('[data-stat="safe"]', String(s.safe || 0));
    setText('[data-stat="suspicious"]', String(s.suspicious || 0));
    setText('[data-stat="scam"]', String(s.scam || 0));
    setText('[data-stat="detectionRate"]', (s.detectionRate != null ? s.detectionRate : 0) + "%");
    const threat = s.mostCommonThreat;
    setText(
      '[data-stat="topThreat"]',
      threat ? threat.label + " (" + threat.count + ")" : "—"
    );
  }

  function renderTypes(types) {
    const select = document.getElementById("typeFilter");
    if (!select) return;
    const current = state.type;
    select.innerHTML = '<option value="all">All</option>';
    (types || []).forEach(function (item) {
      const opt = document.createElement("option");
      opt.value = item.key;
      opt.textContent = item.label;
      select.appendChild(opt);
    });
    select.value = current;
    if (select.value !== current) {
      state.type = "all";
      select.value = "all";
    }
  }

  function renderScansOverTime(payload) {
    const canvas = document.getElementById("scansOverTimeChart");
    if (!canvas) return;
    const tl = payload.timeline || {};
    const labels = tl.labels || [];
    upsertChart("scansOverTimeChart", {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Safe",
            data: payload.empty ? emptyData(labels) : tl.safe || [],
            backgroundColor: "rgba(0,255,163,0.75)",
            borderRadius: 6,
            maxBarThickness: 28,
          },
          {
            label: "Suspicious",
            data: payload.empty ? emptyData(labels) : tl.suspicious || [],
            backgroundColor: "rgba(255,176,32,0.8)",
            borderRadius: 6,
            maxBarThickness: 28,
          },
          {
            label: "Scam",
            data: payload.empty ? emptyData(labels) : tl.scam || [],
            backgroundColor: "rgba(255,56,96,0.8)",
            borderRadius: 6,
            maxBarThickness: 28,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: CHART_LEGEND, tooltip: CHART_TOOLTIP },
        scales: {
          x: {
            stacked: true,
            grid: GRID,
            ticks: CHART_TICK,
            title: { display: true, text: "Date", color: "#6f81a0", font: { size: 11, family: "Rajdhani" } },
          },
          y: {
            stacked: true,
            beginAtZero: true,
            grid: GRID,
            ticks: Object.assign({ precision: 0 }, CHART_TICK),
            title: { display: true, text: "Number of scans", color: "#6f81a0", font: { size: 11, family: "Rajdhani" } },
          },
        },
      },
    });
  }

  function doughnutTooltip(empty, total) {
    return Object.assign({}, CHART_TOOLTIP, {
      callbacks: {
        label: function (ctx) {
          if (empty) return "No scan data available for the selected filters.";
          const val = Number(ctx.parsed) || 0;
          const pct = total ? Math.round((val / total) * 1000) / 10 : 0;
          return (ctx.label || "") + ": " + val + " (" + pct + "%)";
        },
      },
    });
  }

  function renderVerdict(payload) {
    const v = payload.byVerdict || {};
    const values = [v.safe || 0, v.suspicious || 0, v.scam || 0];
    const total = values.reduce(function (a, b) {
      return a + b;
    }, 0);
    const empty = !total;
    upsertChart("verdictChart", {
      type: "doughnut",
      data: {
        labels: empty ? ["No data"] : ["Safe", "Suspicious", "Scam"],
        datasets: [
          {
            data: empty ? [1] : values,
            backgroundColor: empty ? ["rgba(255,255,255,0.08)"] : ["#00ffa3", "#ffb020", "#ff3860"],
            borderColor: "#0d1a2f",
            borderWidth: 2,
            hoverOffset: empty ? 0 : 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: Object.assign({}, CHART_LEGEND, { position: "bottom" }),
          tooltip: doughnutTooltip(empty, total),
        },
      },
    });
  }

  function renderTypeChart(payload) {
    const t = payload.byType || {};
    const labels = t.labels && t.labels.length ? t.labels : ["No data"];
    const values = t.labels && t.labels.length && !payload.empty ? t.values || [] : emptyData(labels);
    upsertChart("typeChart", {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Scans",
            data: values,
            backgroundColor: TYPE_COLORS,
            borderRadius: 6,
            maxBarThickness: 36,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: CHART_TOOLTIP },
        scales: {
          x: { grid: { display: false }, ticks: CHART_TICK },
          y: {
            beginAtZero: true,
            grid: GRID,
            ticks: Object.assign({ precision: 0 }, CHART_TICK),
            title: { display: true, text: "Scans", color: "#6f81a0", font: { size: 11, family: "Rajdhani" } },
          },
        },
      },
    });
  }

  function renderScamType(payload) {
    const t = payload.scamByType || {};
    const hasData = t.values && t.values.length && !payload.empty;
    const total = hasData
      ? t.values.reduce(function (a, b) {
          return a + Number(b || 0);
        }, 0)
      : 0;
    upsertChart("scamTypeChart", {
      type: "doughnut",
      data: {
        labels: hasData ? t.labels : ["No scams"],
        datasets: [
          {
            data: hasData ? t.values : [1],
            backgroundColor: hasData ? TYPE_COLORS : ["rgba(255,255,255,0.08)"],
            borderColor: "#0d1a2f",
            borderWidth: 2,
            hoverOffset: hasData ? 4 : 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "58%",
        plugins: {
          legend: Object.assign({}, CHART_LEGEND, { position: "right" }),
          tooltip: doughnutTooltip(!hasData, total),
        },
      },
    });
  }

  function renderThreatTrend(payload) {
    const canvas = document.getElementById("threatTrendChart");
    if (!canvas) return;
    const trend = payload.threatTrend || {};
    const labels = trend.labels || [];
    upsertChart("threatTrendChart", {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Suspicious + Scam",
            data: payload.empty ? emptyData(labels) : trend.values || [],
            borderColor: "#ff3860",
            backgroundColor: lineGradient(canvas, "rgba(255,56,96,0.32)"),
            pointBackgroundColor: "#ff3860",
            pointRadius: 3,
            pointHoverRadius: 5,
            tension: 0.35,
            fill: true,
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: CHART_LEGEND, tooltip: CHART_TOOLTIP },
        scales: {
          x: { grid: GRID, ticks: CHART_TICK, title: { display: true, text: "Date", color: "#6f81a0", font: { size: 11, family: "Rajdhani" } } },
          y: {
            beginAtZero: true,
            grid: GRID,
            ticks: Object.assign({ precision: 0 }, CHART_TICK),
            title: { display: true, text: "Threat detections", color: "#6f81a0", font: { size: 11, family: "Rajdhani" } },
          },
        },
      },
    });
  }

  function renderTypeDate(payload) {
    const td = payload.typeDate || {};
    const labels = td.dates || [];
    const types = td.types || [];
    const typeLabels = td.labels || [];
    const rows = td.rows || [];
    const datasets = types.map(function (key, i) {
      return {
        label: typeLabels[i] || key,
        data: rows.map(function (row) {
          return payload.empty ? 0 : row[key] || 0;
        }),
        borderColor: TYPE_COLORS[i % TYPE_COLORS.length],
        backgroundColor: TYPE_COLORS[i % TYPE_COLORS.length],
        tension: 0.3,
        fill: false,
        borderWidth: 2,
        pointRadius: 3,
      };
    });

    upsertChart("typeDateChart", {
      type: "line",
      data: { labels: labels, datasets: datasets.length ? datasets : [{ label: "No data", data: emptyData(labels), borderColor: "#6f81a0" }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: CHART_LEGEND, tooltip: CHART_TOOLTIP },
        scales: {
          x: { grid: GRID, ticks: CHART_TICK },
          y: {
            beginAtZero: true,
            grid: GRID,
            ticks: Object.assign({ precision: 0 }, CHART_TICK),
          },
        },
      },
    });

    const host = document.getElementById("typeDateTable");
    if (!host) return;
    if (!rows.length || payload.empty) {
      host.innerHTML = "";
      return;
    }
    let head = "<th>Date</th>";
    typeLabels.forEach(function (label) {
      head += "<th>" + escapeHtml(label) + "</th>";
    });
    const body = rows
      .map(function (row) {
        let cells = "<td class=\"cell-mono\">" + escapeHtml(row.date) + "</td>";
        types.forEach(function (key) {
          cells += "<td class=\"cell-mono\">" + escapeHtml(row[key] || 0) + "</td>";
        });
        return "<tr>" + cells + "</tr>";
      })
      .join("");
    host.innerHTML =
      '<table class="data-table"><thead><tr>' +
      head +
      "</tr></thead><tbody>" +
      body +
      "</tbody></table>";
  }

  function emptyStateHtml(title, copy) {
    return (
      '<div class="empty-state">' +
      "<h3>" +
      escapeHtml(title) +
      "</h3><p>" +
      escapeHtml(copy) +
      "</p></div>"
    );
  }

  function renderRecent(payload) {
    const host = document.getElementById("recentThreatsBody");
    if (!host) return;
    const rows = payload.recentThreats || [];
    if (!rows.length) {
      host.innerHTML = emptyStateHtml(
        "No scan data available for the selected filters.",
        "Suspicious and scam detections in this window will appear here."
      );
      return;
    }
    const body = rows
      .map(function (row) {
        return (
          "<tr>" +
          '<td class="cell-mono">' +
          escapeHtml(row.created_at) +
          "</td>" +
          '<td><span class="type-chip">' +
          escapeHtml(row.scan_type_label) +
          "</span></td>" +
          '<td class="cell-primary" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' +
          escapeHtml(row.input_summary) +
          "</td>" +
          '<td><span class="badge badge-' +
          escapeHtml(row.verdict) +
          '">' +
          escapeHtml(row.verdict) +
          "</span></td>" +
          '<td class="cell-mono">' +
          escapeHtml(row.risk_score) +
          "</td></tr>"
        );
      })
      .join("");
    host.innerHTML =
      '<table class="data-table"><thead><tr><th>Date &amp; Time</th><th>Type</th><th>Input/Target</th><th>Verdict</th><th>Risk Score</th></tr></thead><tbody>' +
      body +
      "</tbody></table>";
  }

  function renderTable(payload) {
    const host = document.getElementById("summaryTableBody");
    if (!host) return;
    const rows = payload.table || [];
    if (!rows.length || payload.empty) {
      host.innerHTML = emptyStateHtml(
        "No scan data available for the selected filters.",
        "Summary totals will appear once matching scans exist."
      );
      return;
    }
    const body = rows
      .map(function (row) {
        return (
          "<tr>" +
          "<td>" +
          escapeHtml(row.label) +
          "</td>" +
          '<td class="cell-mono">' +
          escapeHtml(row.total) +
          "</td>" +
          '<td class="cell-mono">' +
          escapeHtml(row.safe) +
          "</td>" +
          '<td class="cell-mono">' +
          escapeHtml(row.suspicious) +
          "</td>" +
          '<td class="cell-mono">' +
          escapeHtml(row.scam) +
          "</td>" +
          '<td class="cell-mono">' +
          escapeHtml(row.scamPct) +
          "%</td></tr>"
        );
      })
      .join("");
    host.innerHTML =
      '<table class="data-table"><thead><tr><th>Detection Type</th><th>Total</th><th>Safe</th><th>Suspicious</th><th>Scam</th><th>Scam %</th></tr></thead><tbody>' +
      body +
      "</tbody></table>";
  }

  function renderAll(payload) {
    const emptyBanner = document.getElementById("emptyBanner");
    if (emptyBanner) {
      emptyBanner.classList.toggle("is-hidden", !payload.empty);
      emptyBanner.classList.remove("is-error");
      const heading = emptyBanner.querySelector("h3");
      if (heading) heading.textContent = "No scan data available for the selected filters.";
    }
    renderTypes(payload.types);
    renderSummary(payload);
    renderScansOverTime(payload);
    renderVerdict(payload);
    renderTypeChart(payload);
    renderScamType(payload);
    renderThreatTrend(payload);
    renderTypeDate(payload);
    renderRecent(payload);
    renderTable(payload);
  }

  function loadOverview() {
    const url = cfg.overviewUrl;
    if (!url) return;
    fetch(url + "?" + queryString(), {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (res) {
        if (!res.ok) throw new Error("analytics fetch failed");
        return res.json();
      })
      .then(renderAll)
      .catch(function () {
        const emptyBanner = document.getElementById("emptyBanner");
        if (emptyBanner) {
          emptyBanner.classList.remove("is-hidden");
          emptyBanner.classList.add("is-error");
          const heading = emptyBanner.querySelector("h3");
          if (heading) heading.textContent = "Could not load analytics data.";
        }
      });
  }

  function setRangePills() {
    document.querySelectorAll("#rangePills .filter-pill").forEach(function (pill) {
      pill.classList.toggle("active", pill.getAttribute("data-range") === state.range);
    });
    const custom = document.getElementById("customRangeRow");
    if (custom) custom.classList.toggle("is-hidden", state.range !== "custom");
  }

  function bind() {
    document.querySelectorAll("#rangePills .filter-pill").forEach(function (pill) {
      pill.addEventListener("click", function () {
        state.range = pill.getAttribute("data-range") || "30d";
        showRangeError(false);
        setRangePills();
        if (state.range !== "custom") loadOverview();
      });
    });

    const typeFilter = document.getElementById("typeFilter");
    if (typeFilter) {
      typeFilter.addEventListener("change", function () {
        state.type = typeFilter.value || "all";
        loadOverview();
      });
    }

    const verdictFilter = document.getElementById("verdictFilter");
    if (verdictFilter) {
      verdictFilter.addEventListener("change", function () {
        state.verdict = verdictFilter.value || "all";
        loadOverview();
      });
    }

    const rangeError = document.getElementById("rangeError");
    function showRangeError(visible) {
      if (rangeError) rangeError.classList.toggle("is-hidden", !visible);
    }

    const applyBtn = document.getElementById("applyCustomBtn");
    if (applyBtn) {
      applyBtn.addEventListener("click", function () {
        state.start = (document.getElementById("startDate") || {}).value || "";
        state.end = (document.getElementById("endDate") || {}).value || "";
        if (!state.start || !state.end) {
          showRangeError(true);
          return;
        }
        showRangeError(false);
        state.range = "custom";
        setRangePills();
        loadOverview();
      });
    }

    const resetBtn = document.getElementById("resetFiltersBtn");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        state.range = "30d";
        state.type = "all";
        state.verdict = "all";
        state.start = "";
        state.end = "";
        const startEl = document.getElementById("startDate");
        const endEl = document.getElementById("endDate");
        if (startEl) startEl.value = "";
        if (endEl) endEl.value = "";
        if (typeFilter) typeFilter.value = "all";
        if (verdictFilter) verdictFilter.value = "all";
        showRangeError(false);
        setRangePills();
        loadOverview();
      });
    }

    const exportBtn = document.getElementById("exportReportBtn");
    if (exportBtn) {
      exportBtn.addEventListener("click", function () {
        if (!cfg.exportUrl) return;
        window.location.href = cfg.exportUrl + "?" + queryString();
      });
    }
  }

  bind();
  setRangePills();
  loadOverview();
})();
