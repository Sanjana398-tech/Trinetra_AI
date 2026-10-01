(function () {
  "use strict";

  const root = document.getElementById("universalDashboard");
  if (!root) return;

  const overviewUrl = root.dataset.overviewUrl;
  const rangeStatus = document.getElementById("rangeStatus");
  const customDates = document.getElementById("customDates");
  const dateStart = document.getElementById("dateStart");
  const dateEnd = document.getElementById("dateEnd");
  const dashboardError = document.getElementById("dashboardError");
  const mesh = document.getElementById("signalMesh");
  const numberFormat = new Intl.NumberFormat();
  const verdictColors = { safe: "#00e6a0", suspicious: "#f3b840", scam: "#ff5474" };
  let verdictChart;
  let activityChart;
  let selectedRange = "30d";
  let lastPayload;

  function formatCount(value) {
    return numberFormat.format(Number(value) || 0);
  }

  function updateSummary(summary) {
    document.querySelectorAll("[data-summary]").forEach(function (element) {
      const key = element.dataset.summary;
      element.textContent = key in summary ? formatCount(summary[key]) : "0";
    });
    document.getElementById("meshTotal").textContent = formatCount(summary.totalScans);
    document.getElementById("verdictTotal").textContent = formatCount(summary.totalScans);
  }

  function updateChannels(channels) {
    const list = document.getElementById("channelList");
    const maximum = Math.max(1, ...channels.map(function (item) { return item.count; }));
    list.innerHTML = channels.map(function (item) {
      const width = Math.max(0, Math.min(100, (item.count / maximum) * 100));
      return '<div class="channel-row"><span class="channel-name">' + item.label +
        '</span><div class="channel-track"><div class="channel-fill" style="width:' + width +
        '%"></div></div><span class="channel-count">' + formatCount(item.count) + '</span></div>';
    }).join("");
  }

  function updateVerdicts(payload) {
    const distribution = payload.verdictDistribution;
    const keys = ["safe", "suspicious", "scam"];
    const values = keys.map(function (key) { return distribution[key] || 0; });
    if (verdictChart) {
      verdictChart.data.datasets[0].data = values;
      verdictChart.update();
    } else if (window.Chart) {
      verdictChart = new Chart(document.getElementById("verdictChart"), {
        type: "doughnut",
        data: { labels: ["Safe", "Suspicious", "Scam"], datasets: [{ data: values, backgroundColor: keys.map(function (key) { return verdictColors[key]; }), borderWidth: 0, hoverOffset: 5 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: "78%", plugins: { legend: { display: false }, tooltip: { callbacks: { label: function (context) { return " " + context.label + ": " + formatCount(context.raw); } } } } },
      });
    }
    document.getElementById("verdictLegend").innerHTML = keys.map(function (key) {
      return '<div><span class="verdict-label"><i class="verdict-swatch" style="background:' + verdictColors[key] + '"></i>' +
        key.charAt(0).toUpperCase() + key.slice(1) + '</span><span class="verdict-count">' + formatCount(distribution[key]) + '</span></div>';
    }).join("");
  }

  function updateActivity(activity) {
    const labels = activity.map(function (item) {
      const parts = item.date.split("-");
      return new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2])).toLocaleDateString(undefined, { month: "short", day: "numeric" });
    });
    const keys = ["safe", "suspicious", "scam"];
    const datasets = keys.map(function (key) {
      return { label: key.charAt(0).toUpperCase() + key.slice(1), data: activity.map(function (item) { return item[key]; }), borderColor: verdictColors[key], backgroundColor: verdictColors[key] + "22", pointRadius: 2, pointHoverRadius: 4, borderWidth: 2, tension: 0.32, fill: false };
    });
    if (activityChart) {
      activityChart.data.labels = labels;
      activityChart.data.datasets.forEach(function (dataset, index) { dataset.data = datasets[index].data; });
      activityChart.update();
    } else if (window.Chart) {
      activityChart = new Chart(document.getElementById("activityChart"), {
        type: "line",
        data: { labels: labels, datasets: datasets },
        options: { responsive: true, maintainAspectRatio: false, interaction: { mode: "index", intersect: false }, plugins: { legend: { labels: { color: "#aebdd4", usePointStyle: true, boxWidth: 7, font: { family: "Rajdhani", size: 12 } } } }, scales: { x: { grid: { color: "rgba(154,190,210,0.08)" }, ticks: { color: "#768aa1", maxTicksLimit: 9, maxRotation: 0 } }, y: { beginAtZero: true, grid: { color: "rgba(154,190,210,0.08)" }, ticks: { color: "#768aa1", precision: 0 } } } },
      });
    }
  }

  function selectRange(range) {
    selectedRange = range;
    document.querySelectorAll("[data-range]").forEach(function (button) {
      const active = button.dataset.range === range;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    customDates.hidden = range !== "custom";
    if (range !== "custom") loadOverview({ range: range });
  }

  async function loadOverview(filters) {
    dashboardError.hidden = true;
    rangeStatus.textContent = "Updating aggregate telemetry…";
    const params = new URLSearchParams(filters);
    try {
      const response = await fetch(overviewUrl + "?" + params.toString(), { headers: { Accept: "application/json" } });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Could not load aggregate telemetry.");
      lastPayload = payload;
      updateSummary(payload.summary);
      updateChannels(payload.channels);
      updateVerdicts(payload);
      updateActivity(payload.dateActivity);
      rangeStatus.textContent = payload.filters.start === payload.filters.end ? payload.filters.start : payload.filters.start + " — " + payload.filters.end;
    } catch (error) {
      dashboardError.textContent = error.message || "Could not load the Universal Security Dashboard.";
      dashboardError.hidden = false;
      rangeStatus.textContent = "Telemetry unavailable";
    }
  }

  document.querySelectorAll(".range-selector [data-range]").forEach(function (button) {
    button.addEventListener("click", function () { selectRange(button.dataset.range); });
  });

  document.getElementById("applyCustom").addEventListener("click", function () {
    if (!dateStart.value || !dateEnd.value) {
      dashboardError.textContent = "Choose both a start date and an end date.";
      dashboardError.hidden = false;
      return;
    }
    loadOverview({ range: "custom", start: dateStart.value, end: dateEnd.value });
  });

  document.querySelectorAll("[data-mesh-mode]").forEach(function (button) {
    button.addEventListener("click", function () {
      document.querySelectorAll("[data-mesh-mode]").forEach(function (candidate) {
        const active = candidate === button;
        candidate.classList.toggle("is-active", active);
        candidate.setAttribute("aria-pressed", String(active));
      });
      mesh.dataset.mode = button.dataset.meshMode;
      if (lastPayload) {
        const signalCount = button.dataset.meshMode === "threats"
          ? lastPayload.summary.scam + lastPayload.summary.suspicious
          : lastPayload.summary.totalScans;
        document.getElementById("meshTotal").textContent = formatCount(signalCount);
        document.querySelector(".mesh-center small").textContent = button.dataset.meshMode === "threats" ? "THREAT SIGNALS" : "SCANS IN RANGE";
      }
    });
  });

  loadOverview({ range: selectedRange });
}());