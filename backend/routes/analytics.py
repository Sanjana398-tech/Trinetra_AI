"""
TRINETRA AI - Advanced Analytics Routes
=========================================
SOC-style analytics over the logged-in user's ScanHistory.

Routes:
    GET /analytics
    GET /api/analytics/overview
    GET /api/analytics/summary
    GET /api/analytics/timeline
    GET /api/analytics/by-type
    GET /api/analytics/by-verdict
    GET /api/analytics/type-date
    GET /api/analytics/recent-threats
    GET /api/analytics/export
"""

import csv
import io
from datetime import datetime

from flask import Blueprint, Response, jsonify, render_template, request, url_for
from flask_login import current_user, login_required

from backend.utils.analytics_query import (
    build_by_type,
    build_overview,
    build_recent_threats,
    build_scam_by_type,
    build_summary,
    build_table,
    build_timeline,
    build_type_date,
    filtered_query,
    iter_export_rows,
    parse_filters,
)

analytics_bp = Blueprint("analytics", __name__)


def _query_bundle():
    filters = parse_filters(request.args)
    query = filtered_query(current_user, filters)
    return filters, query


@analytics_bp.route("/analytics")
@login_required
def analytics_page():
    return render_template(
        "analytics.html",
        active_page="analytics",
        page_title="Advanced Analytics",
        overview_url=url_for("analytics.overview_api"),
        export_url=url_for("analytics.export_csv"),
    )


@analytics_bp.route("/api/analytics/overview")
@login_required
def overview_api():
    """Single payload for the analytics page (avoids six round-trips)."""
    return jsonify(build_overview(current_user, request.args))


@analytics_bp.route("/api/analytics/summary")
@login_required
def summary_api():
    filters, query = _query_bundle()
    return jsonify({"filters": filters["range"], "summary": build_summary(query)})


@analytics_bp.route("/api/analytics/timeline")
@login_required
def timeline_api():
    filters, query = _query_bundle()
    return jsonify(build_timeline(query, filters))


@analytics_bp.route("/api/analytics/by-type")
@login_required
def by_type_api():
    _filters, query = _query_bundle()
    return jsonify({
        "byType": build_by_type(query),
        "scamByType": build_scam_by_type(query),
        "table": build_table(query),
    })


@analytics_bp.route("/api/analytics/by-verdict")
@login_required
def by_verdict_api():
    _filters, query = _query_bundle()
    summary = build_summary(query)
    return jsonify({
        "safe": summary["safe"],
        "suspicious": summary["suspicious"],
        "scam": summary["scam"],
    })


@analytics_bp.route("/api/analytics/type-date")
@login_required
def type_date_api():
    filters, query = _query_bundle()
    return jsonify(build_type_date(query, filters))


@analytics_bp.route("/api/analytics/recent-threats")
@login_required
def recent_threats_api():
    _filters, query = _query_bundle()
    return jsonify({"items": build_recent_threats(query)})


@analytics_bp.route("/api/analytics/export")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["Date", "Detection Type", "Input/Target", "Verdict", "Risk Score", "Confidence"]
    )
    for row in iter_export_rows(current_user, request.args):
        writer.writerow(
            [
                row["created_at"],
                row["scan_type_label"],
                row["input_summary"],
                row["verdict"],
                row["risk_score"],
                row["confidence_score"],
            ]
        )
    stamp = datetime.utcnow().strftime("%Y%m%d")
    filename = f"trinetra-analytics-{stamp}.csv"
    payload = "\ufeff" + output.getvalue()
    return Response(
        payload,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
