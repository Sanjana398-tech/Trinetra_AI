/**
 * TRINETRA AI - Global UI behaviour
 * Sidebar collapse/open, theme toggle, recent-scans filter pills.
 * No external dependencies; keeps the shell interactive even before
 * any AI module JS is loaded.
 */
(function () {
  "use strict";

  // ---------------------------------------------------------------------
  // Sidebar toggle (collapse on desktop, slide-over on mobile)
  // ---------------------------------------------------------------------
  const toggleBtn = document.getElementById("sidebarToggle");
  const isMobile = () => window.matchMedia("(max-width: 980px)").matches;

  if (toggleBtn) {
    toggleBtn.addEventListener("click", function () {
      if (isMobile()) {
        document.body.classList.toggle("sidebar-open");
      } else {
        document.body.classList.toggle("sidebar-collapsed");
        try {
          localStorage.setItem(
            "trinetra_sidebar_collapsed",
            document.body.classList.contains("sidebar-collapsed") ? "1" : "0"
          );
        } catch (e) {
          /* localStorage unavailable — non-fatal, just skip persistence */
        }
      }
    });
  }

  try {
    if (!isMobile() && localStorage.getItem("trinetra_sidebar_collapsed") === "1") {
      document.body.classList.add("sidebar-collapsed");
    }
  } catch (e) {
    /* ignore */
  }

  // Close mobile sidebar when clicking outside it
  document.addEventListener("click", function (evt) {
    if (!isMobile()) return;
    const sidebar = document.getElementById("sidebar");
    if (!sidebar || !document.body.classList.contains("sidebar-open")) return;
    if (sidebar.contains(evt.target) || evt.target === toggleBtn || toggleBtn?.contains(evt.target)) return;
    document.body.classList.remove("sidebar-open");
  });

  // ---------------------------------------------------------------------
  // Theme toggle (dark = default "watchful" theme, light = daylight mode)
  // ---------------------------------------------------------------------
  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    try {
      const saved = localStorage.getItem("trinetra_theme");
      if (saved === "light") {
        document.documentElement.classList.add("light-mode");
        themeToggle.checked = false;
      }
    } catch (e) {
      /* ignore */
    }

    themeToggle.addEventListener("change", function () {
      document.documentElement.classList.toggle("light-mode", !themeToggle.checked);
      try {
        localStorage.setItem("trinetra_theme", themeToggle.checked ? "dark" : "light");
      } catch (e) {
        /* ignore */
      }
    });
  }

  // ---------------------------------------------------------------------
  // Recent scans: verdict filter pills
  // ---------------------------------------------------------------------
  const pills = document.querySelectorAll(".filter-pill");
  const rows = document.querySelectorAll("#recentScansTable tbody tr");

  pills.forEach(function (pill) {
    pill.addEventListener("click", function () {
      pills.forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      const filter = pill.getAttribute("data-filter");

      rows.forEach(function (row) {
        const matches = filter === "all" || row.getAttribute("data-verdict") === filter;
        row.style.display = matches ? "" : "none";
      });
    });
  });

  // ---------------------------------------------------------------------
  // Drop zones — drag-over highlight + filename display
  // ---------------------------------------------------------------------
  document.querySelectorAll(".drop-zone").forEach(function (zone) {
    const input = zone.querySelector('input[type="file"]');
    const nameEl = zone.querySelector(".drop-zone-filename");
    const titleEl = zone.querySelector(".drop-zone-title");

    zone.addEventListener("dragover", function (e) {
      e.preventDefault();
      zone.classList.add("drag-over");
    });
    zone.addEventListener("dragleave", function () {
      zone.classList.remove("drag-over");
    });
    zone.addEventListener("drop", function (e) {
      e.preventDefault();
      zone.classList.remove("drag-over");
      if (input && e.dataTransfer.files.length) {
        // Transfer files to the real input
        const dt = new DataTransfer();
        dt.items.add(e.dataTransfer.files[0]);
        input.files = dt.files;
        input.dispatchEvent(new Event("change"));
      }
    });

    if (input && nameEl) {
      input.addEventListener("change", function () {
        if (input.files && input.files[0]) {
          nameEl.style.display = "inline-block";
          nameEl.textContent = input.files[0].name;
          if (titleEl) titleEl.textContent = "File selected";
        }
      });
    }
  });

  // ---------------------------------------------------------------------
  // Character counters
  // ---------------------------------------------------------------------
  document.querySelectorAll("[data-char-counter]").forEach(function (el) {
    const target = document.getElementById(el.getAttribute("data-char-counter"));
    if (!target) return;
    const max = parseInt(target.getAttribute("maxlength") || "4000", 10);

    function update() {
      const len = target.value.length;
      el.textContent = len + " / " + max;
      el.classList.toggle("warn", len > max * 0.8);
      el.classList.toggle("danger", len > max * 0.95);
    }

    target.addEventListener("input", update);
    update();
  });

  // ---------------------------------------------------------------------
  // Scan form submit — loading state on the submit button
  // ---------------------------------------------------------------------
  document.querySelectorAll("form[data-scan-form]").forEach(function (form) {
    form.addEventListener("submit", function () {
      const btn = form.querySelector("button[type='submit']");
      if (btn) {
        btn.classList.add("scanning");
        btn.innerHTML = btn.innerHTML.replace(/Analyze|Transcribe|Decode|Extract|Scan/i, "Scanning…");
      }
    });
  });

  // Message scans use the same API as Secure Chat so both clients persist
  // results through one backend path.
  const messageScanForm = document.querySelector("form[data-message-api-url]");
  if (messageScanForm) {
    const messageInput = messageScanForm.querySelector("#message_text");
    const messageButton = messageScanForm.querySelector("button[type='submit']");
    const messageError = document.getElementById("messageScanError");
    const messageResult = document.getElementById("messageScanResult");
    const originalButtonMarkup = messageButton ? messageButton.innerHTML : "";

    function escapeHtml(value) {
      return String(value == null ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;");
    }

    function showMessageError(text) {
      if (!messageError) return;
      messageError.textContent = text;
      messageError.hidden = false;
      if (messageResult) messageResult.hidden = true;
    }

    messageScanForm.addEventListener("submit", async function (event) {
      event.preventDefault();

      const message = (messageInput ? messageInput.value : "").trim();
      if (!message) {
        showMessageError("Please paste a message to analyze.");
        return;
      }

      if (messageButton) {
        messageButton.disabled = true;
        messageButton.textContent = "Analyzing...";
      }
      if (messageError) messageError.hidden = true;

      try {
        const response = await fetch(messageScanForm.dataset.messageApiUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: message }),
        });
        const payload = await response.json();

        if (!response.ok || !payload.success) {
          throw new Error(payload.error || "Message analysis failed.");
        }

        const requiredFields = [
          "prediction",
          "confidence",
          "safe_probability",
          "scam_probability",
          "scan_id",
        ];
        const missingField = requiredFields.find(function (field) {
          return payload[field] === undefined || payload[field] === null;
        });
        if (missingField) {
          throw new Error("Analysis response is missing " + missingField + ".");
        }

        const verdict = String(payload.prediction).toLowerCase();
        const scanId = encodeURIComponent(payload.scan_id);
        if (messageResult) {
          messageResult.innerHTML =
            '<div class="verdict-hero ' + escapeHtml(verdict) + '" style="margin-top:24px;">' +
            '<div class="vh-icon">' + escapeHtml(payload.prediction) + '</div>' +
            '<div><div class="vh-title">' + escapeHtml(payload.prediction_label || payload.prediction) + '</div>' +
            '<p class="vh-sub">' + escapeHtml(payload.alert || "Message analyzed by DistilBERT and saved to Scan History.") + '</p></div>' +
            '<div class="verdict-ring-wrap"><div class="vh-score-secondary">' +
            '<div class="num">' + escapeHtml(payload.confidence) + '%</div>' +
            '<div class="lbl">' + escapeHtml(payload.confidence_label || "Confidence") + '</div></div></div></div>' +
            '<div class="detail-grid" style="margin-bottom:20px;">' +
            '<div class="glass-panel"><div class="panel-head"><div><h2>' + escapeHtml(payload.probability_label || "Probability") + '</h2>' +
            '<div class="panel-sub">DistilBERT output</div></div></div><div class="panel-body">' +
            '<div class="prob-bars"><div class="prob-row"><div class="prob-label-row">' +
            '<span class="prob-label">' + escapeHtml(payload.safe_label || "Safe") + '</span><span class="prob-value">' + escapeHtml(payload.safe_probability) +
            '%</span></div><div class="prob-track"><div class="prob-fill safe-fill" style="width:' +
            escapeHtml(payload.safe_probability) + '%"></div></div></div>' +
            '<div class="prob-row"><div class="prob-label-row"><span class="prob-label">' + escapeHtml(payload.scam_label || "Scam") + '</span>' +
            '<span class="prob-value">' + escapeHtml(payload.scam_probability) +
            '%</span></div><div class="prob-track"><div class="prob-fill scam-fill" style="width:' +
            escapeHtml(payload.scam_probability) + '%"></div></div></div></div></div></div>' +
            '<div class="glass-panel"><div class="panel-body"><a class="btn btn-ghost btn-block" href="/history/' +
            scanId + '">' + escapeHtml(payload.view_record_label || "View Full Scan Record") + '</a></div></div></div>';
          messageResult.hidden = false;
          messageResult.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      } catch (error) {
        showMessageError(error.message || "Unable to reach the analysis API.");
      } finally {
        if (messageButton) {
          messageButton.disabled = false;
          messageButton.innerHTML = originalButtonMarkup;
        }
      }
    });
  }

  // ---------------------------------------------------------------------
  // Verdict confidence ring animation
  // ---------------------------------------------------------------------
  document.querySelectorAll(".verdict-ring[data-confidence]").forEach(function (ring) {
    const fill = ring.querySelector(".vr-fill");
    if (!fill) return;
    const r = parseFloat(fill.getAttribute("r") || "35");
    const circ = 2 * Math.PI * r;
    const conf = Math.min(100, Math.max(0, parseFloat(ring.getAttribute("data-confidence") || "0")));
    fill.setAttribute("stroke-dasharray", circ.toFixed(2));
    fill.setAttribute("stroke-dashoffset", circ.toFixed(2));
    // Animate after paint
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        fill.style.strokeDashoffset = (circ * (1 - conf / 100)).toFixed(2);
      });
    });
  });

})();
