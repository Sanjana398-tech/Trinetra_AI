/**
 * TRINETRA AI - Dashboard visualizations
 * Renders Chart.js graphs from live ScanHistory stats and keeps the
 * dashboard fresh via periodic / focus AJAX polling.
 */
(function () {
  "use strict";

  let data = window.__TRINETRA_DASHBOARD__ || {};
  let trendChart = null;
  let typeChart = null;
  let riskChart = null;

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

  const TYPE_COLORS = ["#00e5ff", "#7b61ff", "#ffb020", "#ff3860", "#00ffa3"];
  const RISK_COLORS = ["#00ffa3", "#ffb020", "#ff3860"];

  // ---------------------------------------------------------------------
  // Risk ring
  // ---------------------------------------------------------------------
  function updateRiskRing(score) {
    const ring = document.getElementById("riskRingFill");
    if (!ring) return;

    const circumference = 2 * Math.PI * 50;
    const clamped = Math.max(0, Math.min(100, Number(score) || 0));
    const offset = circumference * (1 - clamped / 100);

    let color = "var(--safe)";
    if (clamped < 40) color = "var(--danger)";
    else if (clamped < 75) color = "var(--warn)";
    ring.style.stroke = color;
    ring.style.strokeDashoffset = String(offset);
  }

  // ---------------------------------------------------------------------
  // Charts
  // ---------------------------------------------------------------------
  function buildTrendChart(payload) {
    const canvas = document.getElementById("trendChart");
    if (!canvas || !window.Chart) return;

    const ctx = canvas.getContext("2d");
    const scamGradient = ctx.createLinearGradient(0, 0, 0, 240);
    scamGradient.addColorStop(0, "rgba(255, 56, 96, 0.35)");
    scamGradient.addColorStop(1, "rgba(255, 56, 96, 0)");

    const safeGradient = ctx.createLinearGradient(0, 0, 0, 240);
    safeGradient.addColorStop(0, "rgba(0, 229, 255, 0.30)");
    safeGradient.addColorStop(1, "rgba(0, 229, 255, 0)");

    const suspiciousGradient = ctx.createLinearGradient(0, 0, 0, 240);
    suspiciousGradient.addColorStop(0, "rgba(255, 176, 32, 0.28)");
    suspiciousGradient.addColorStop(1, "rgba(255, 176, 32, 0)");

    const config = {
      type: "line",
      data: {
        labels: payload.trendLabels || [],
        datasets: [
          {
            label: "Scam",
            data: payload.trendScam || [],
            borderColor: "#ff3860",
            backgroundColor: scamGradient,
            pointBackgroundColor: "#ff3860",
            pointRadius: 3,
            pointHoverRadius: 5,
            tension: 0.4,
            fill: true,
            borderWidth: 2,
          },
          {
            label: "Suspicious",
            data: payload.trendSuspicious || [],
            borderColor: "#ffb020",
            backgroundColor: suspiciousGradient,
            pointBackgroundColor: "#ffb020",
            pointRadius: 3,
            pointHoverRadius: 5,
            tension: 0.4,
            fill: true,
            borderWidth: 2,
          },
          {
            label: "Safe",
            data: payload.trendSafe || [],
            borderColor: "#00e5ff",
            backgroundColor: safeGradient,
            pointBackgroundColor: "#00e5ff",
            pointRadius: 3,
            pointHoverRadius: 5,
            tension: 0.4,
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
          x: { grid: GRID, ticks: CHART_TICK },
          y: {
            beginAtZero: true,
            grid: GRID,
            ticks: Object.assign({ precision: 0 }, CHART_TICK),
          },
        },
      },
    };

    if (trendChart) {
      trendChart.data.labels = config.data.labels;
      trendChart.data.datasets.forEach(function (ds, i) {
        ds.data = config.data.datasets[i].data;
      });
      trendChart.update("none");
    } else {
      trendChart = new window.Chart(ctx, config);
    }
  }

  function buildTypeChart(payload) {
    const canvas = document.getElementById("typeDistChart");
    if (!canvas || !window.Chart) return;

    const labels = payload.typeLabels || ["Message", "URL", "QR", "Voice", "Payment"];
    const values = payload.typeValues || [0, 0, 0, 0, 0];

    if (typeChart) {
      typeChart.data.labels = labels;
      typeChart.data.datasets[0].data = values;
      typeChart.update("none");
      return;
    }

    typeChart = new window.Chart(canvas.getContext("2d"), {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: TYPE_COLORS,
            borderColor: "#0d1a2f",
            borderWidth: 2,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: Object.assign({}, CHART_LEGEND, { position: "right" }),
          tooltip: CHART_TOOLTIP,
        },
      },
    });
  }

  function buildRiskChart(payload) {
    const canvas = document.getElementById("riskLevelChart");
    if (!canvas || !window.Chart) return;

    const levels = payload.riskLevels || { low: 0, medium: 0, high: 0 };
    const values = [levels.low || 0, levels.medium || 0, levels.high || 0];

    if (riskChart) {
      riskChart.data.datasets[0].data = values;
      riskChart.update("none");
      return;
    }

    riskChart = new window.Chart(canvas.getContext("2d"), {
      type: "bar",
      data: {
        labels: ["Low", "Medium", "High"],
        datasets: [
          {
            label: "Scans",
            data: values,
            backgroundColor: RISK_COLORS,
            borderRadius: 6,
            maxBarThickness: 36,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: CHART_TOOLTIP,
        },
        scales: {
          x: { grid: { display: false }, ticks: CHART_TICK },
          y: {
            beginAtZero: true,
            grid: GRID,
            ticks: Object.assign({ precision: 0 }, CHART_TICK),
          },
        },
      },
    });
  }

  // ---------------------------------------------------------------------
  // DOM updates (stat cards, channel bars, recent table)
  // ---------------------------------------------------------------------
  function setText(selector, value) {
    document.querySelectorAll(selector).forEach(function (el) {
      el.textContent = value;
    });
  }

  function updateChannelBars(typeCounts) {
    const counts = typeCounts || {};
    const values = Object.keys(counts).map(function (k) {
      return counts[k] || 0;
    });
    const maxCount = Math.max.apply(null, values.concat([1]));

    ["message", "url", "qr", "voice", "screenshot"].forEach(function (key) {
      const count = counts[key] || 0;
      const bar = document.querySelector('[data-channel-bar="' + key + '"]');
      const label = document.querySelector('[data-channel-count="' + key + '"]');
      if (bar) bar.style.width = Math.round((count / maxCount) * 100) + "%";
      if (label) label.textContent = String(count);
    });
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderRecent(rows) {
    const host = document.getElementById("recentScansBody");
    if (!host) return;

    if (!rows || !rows.length) {
      host.innerHTML =
        '<div class="empty-state" id="recentEmptyState">' +
        "<h3>No scans yet</h3>" +
        "<p>Run your first scan from a Quick Scan tile above and it will show up here.</p>" +
        "</div>";
      return;
    }

    const body = rows
      .map(function (scan) {
        return (
          '<tr data-verdict="' +
          escapeHtml(scan.verdict) +
          '">' +
          '<td><span class="type-chip">' +
          escapeHtml(scan.scan_type_label || scan.scan_type) +
          "</span></td>" +
          '<td class="cell-primary" style="max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">' +
          '<a href="' +
          escapeHtml(scan.detail_url) +
          '" style="color:inherit;">' +
          escapeHtml(scan.input_summary) +
          "</a></td>" +
          '<td><span class="badge badge-' +
          escapeHtml(scan.verdict) +
          '">' +
          escapeHtml(scan.verdict) +
          "</span></td>" +
          '<td class="cell-mono">' +
          escapeHtml(scan.confidence_score) +
          "%</td>" +
          '<td class="cell-mono">' +
          escapeHtml(scan.created_at) +
          "</td>" +
          "</tr>"
        );
      })
      .join("");

    host.innerHTML =
      '<table class="data-table" id="recentScansTable">' +
      "<thead><tr><th>Channel</th><th>Input</th><th>Verdict</th><th>Confidence</th><th>Scanned</th></tr></thead>" +
      "<tbody>" +
      body +
      "</tbody></table>";

    bindFilterPills();
  }

  function bindFilterPills() {
    const pills = document.querySelectorAll(".filter-pill");
    const tableRows = document.querySelectorAll("#recentScansTable tbody tr");
    pills.forEach(function (pill) {
      pill.onclick = function () {
        pills.forEach(function (p) {
          p.classList.remove("active");
        });
        pill.classList.add("active");
        const filter = pill.getAttribute("data-filter");
        tableRows.forEach(function (row) {
          const verdict = row.getAttribute("data-verdict");
          row.style.display = filter === "all" || filter === verdict ? "" : "none";
        });
      };
    });
  }

  function applyPayload(payload) {
    data = payload || data;
    setText('[data-stat="total"]', String(data.total || 0));
    setText('[data-stat="trust"]', (data.trustScore != null ? data.trustScore : 0) + "%");
    setText('[data-stat="trustLabel"]', (data.trustScore != null ? data.trustScore : 0) + "%");
    setText('[data-stat="scam"]', String(data.scam || 0));
    setText('[data-stat="scamLegend"]', String(data.scam || 0));
    setText('[data-stat="avgRisk"]', String(data.avgRisk != null ? data.avgRisk : 0));
    setText('[data-stat="safe"]', String(data.safe || 0));
    setText('[data-stat="suspicious"]', String(data.suspicious || 0));

    updateRiskRing(data.trustScore);
    updateChannelBars(data.typeCounts);
    buildTrendChart(data);
    buildTypeChart(data);
    buildRiskChart(data);
    if (data.recent) renderRecent(data.recent);
  }

  // ---------------------------------------------------------------------
  // Live refresh (AJAX) — after new scans, focus, or every 20s
  // ---------------------------------------------------------------------
  let lastFingerprint = "";

  function fingerprint(payload) {
    return JSON.stringify({
      total: payload.total,
      safe: payload.safe,
      suspicious: payload.suspicious,
      scam: payload.scam,
      avgRisk: payload.avgRisk,
      trustScore: payload.trustScore,
      typeCounts: payload.typeCounts,
      riskLevels: payload.riskLevels,
      trendScam: payload.trendScam,
      trendSafe: payload.trendSafe,
      trendSuspicious: payload.trendSuspicious,
      recentIds: (payload.recent || []).map(function (r) {
        return r.id;
      }),
    });
  }

  function refreshStats() {
    const url = data.statsUrl;
    if (!url) return;

    fetch(url, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    })
      .then(function (res) {
        if (!res.ok) throw new Error("stats fetch failed");
        return res.json();
      })
      .then(function (payload) {
        payload.statsUrl = url;
        const next = fingerprint(payload);
        if (next === lastFingerprint) return;
        lastFingerprint = next;
        applyPayload(payload);
      })
      .catch(function () {
        /* keep last good snapshot on transient errors */
      });
  }

  // Initial render from server-injected payload
  lastFingerprint = fingerprint(data);
  updateRiskRing(data.trustScore);
  buildTrendChart(data);
  buildTypeChart(data);
  buildRiskChart(data);
  bindFilterPills();

  // Animated counters only on first paint
  document.querySelectorAll(".stat-value").forEach(function (el) {
    const raw = el.textContent.trim();
    const match = raw.match(/^([\d.]+)(.*)$/);
    if (!match) return;

    const target = parseFloat(match[1]);
    const suffix = match[2] || "";
    const duration = 900;
    const start = performance.now();

    function frame(now) {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = target * eased;
      el.textContent = (Number.isInteger(target) ? Math.round(value) : value.toFixed(1)) + suffix;
      if (progress < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  });

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) refreshStats();
  });
  window.addEventListener("focus", refreshStats);
  setInterval(refreshStats, 20000);
})();
