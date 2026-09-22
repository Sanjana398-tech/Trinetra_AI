"""
TRINETRA AI - Dashboard Routes
================================
Serves the main cybersecurity dashboard: live statistics, threat
summary, risk overview and the recent-scans feed. All numbers are
computed from the database (ScanHistory) for the logged-in user —
never hardcoded or seeded demo rows.
"""

from collections import Counter
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, render_template, url_for
from flask_login import login_required, current_user

from backend.db_models import ScanHistory
from backend.utils.channels import CHANNEL_LABELS, CHANNEL_TYPES
from backend.utils.scan_visibility import visible_scans_query

dashboard_bp = Blueprint("dashboard", __name__)


def _serialize_recent(scans):
    """Turn ScanHistory rows into JSON-friendly dicts for the live API / charts."""
    items = []
    for scan in scans:
        try:
            detail_url = url_for("history.view_record", record_id=scan.id)
        except RuntimeError:
            # Outside a request (e.g. unit harness) — fall back to the known path.
            detail_url = f"/history/{scan.id}"
        items.append(
            {
                "id": scan.id,
                "scan_type": scan.scan_type,
                "scan_type_label": CHANNEL_LABELS.get(scan.scan_type, scan.scan_type.capitalize()),
                "input_summary": scan.input_summary,
                "verdict": scan.verdict,
                "confidence_score": scan.confidence_score,
                "risk_score": scan.risk_score,
                "created_at": scan.created_at.strftime("%d %b, %I:%M %p"),
                "detail_url": detail_url,
            }
        )
    return items


def _compute_stats(user):
    """Aggregate the current user's ScanHistory into dashboard-ready statistics."""
    all_scans = visible_scans_query(user).order_by(ScanHistory.created_at.desc()).all()

    total = len(all_scans)
    verdict_counts = Counter(s.verdict for s in all_scans)
    raw_type_counts = Counter(s.scan_type for s in all_scans)

    # Always expose every channel key so charts/bars stay stable when a type is 0.
    type_counts = {key: raw_type_counts.get(key, 0) for key in CHANNEL_TYPES}

    safe = verdict_counts.get("safe", 0)
    suspicious = verdict_counts.get("suspicious", 0)
    scam = verdict_counts.get("scam", 0)

    trust_score = round((safe / total) * 100, 1) if total else 100.0
    avg_risk = round(sum(s.risk_score for s in all_scans) / total, 1) if total else 0.0

    # Risk-level buckets for distribution (low / medium / high by risk_score).
    risk_low = sum(1 for s in all_scans if s.risk_score < 40)
    risk_medium = sum(1 for s in all_scans if 40 <= s.risk_score < 70)
    risk_high = sum(1 for s in all_scans if s.risk_score >= 70)

    # Last 7 days trend, oldest -> newest
    today = datetime.utcnow().date()
    trend_labels, trend_scam, trend_safe, trend_suspicious, trend_total = [], [], [], [], []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        day_scans = [s for s in all_scans if s.created_at.date() == day]
        trend_labels.append(day.strftime("%d %b"))
        trend_scam.append(sum(1 for s in day_scans if s.verdict == "scam"))
        trend_safe.append(sum(1 for s in day_scans if s.verdict == "safe"))
        trend_suspicious.append(sum(1 for s in day_scans if s.verdict == "suspicious"))
        trend_total.append(len(day_scans))

    recent_rows = all_scans[:8]

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "scam": scam,
        "trust_score": trust_score,
        "avg_risk": avg_risk,
        "type_counts": type_counts,
        "type_labels": [CHANNEL_LABELS[k] for k in CHANNEL_TYPES],
        "type_values": [type_counts[k] for k in CHANNEL_TYPES],
        "risk_levels": {
            "low": risk_low,
            "medium": risk_medium,
            "high": risk_high,
        },
        "trend_labels": trend_labels,
        "trend_scam": trend_scam,
        "trend_safe": trend_safe,
        "trend_suspicious": trend_suspicious,
        "trend_total": trend_total,
        "recent": recent_rows,
        "recent_serialized": _serialize_recent(recent_rows),
    }


def _stats_payload(stats):
    """JSON payload for Chart.js / AJAX live updates (no ORM objects)."""
    return {
        "total": stats["total"],
        "safe": stats["safe"],
        "suspicious": stats["suspicious"],
        "scam": stats["scam"],
        "trustScore": stats["trust_score"],
        "avgRisk": stats["avg_risk"],
        "typeCounts": stats["type_counts"],
        "typeLabels": stats["type_labels"],
        "typeValues": stats["type_values"],
        "riskLevels": stats["risk_levels"],
        "trendLabels": stats["trend_labels"],
        "trendScam": stats["trend_scam"],
        "trendSafe": stats["trend_safe"],
        "trendSuspicious": stats["trend_suspicious"],
        "trendTotal": stats["trend_total"],
        "recent": stats["recent_serialized"],
    }


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    stats = _compute_stats(current_user)
    return render_template(
        "dashboard.html",
        stats=stats,
        channel_labels=CHANNEL_LABELS,
        active_page="dashboard",
        page_title="Security Dashboard",
    )


@dashboard_bp.route("/api/dashboard/stats")
@login_required
def dashboard_stats_api():
    """Live JSON stats for the dashboard (poll after new scans / on focus)."""
    stats = _compute_stats(current_user)
    return jsonify(_stats_payload(stats))


@dashboard_bp.route("/light-mode-demo")
def light_mode_demo():
    """Standalone demo page for testing light mode styling without authentication."""
    return render_template("light-mode-demo.html")
