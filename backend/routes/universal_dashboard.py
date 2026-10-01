"""Privacy-preserving, cross-account security dashboard aggregates."""

from datetime import date, datetime, time, timedelta

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required
from sqlalchemy import func

from backend.db_models import ScanHistory, User
from backend.utils.channels import channel_label

universal_dashboard_bp = Blueprint("universal_dashboard", __name__)

_CHANNELS = (
    ("message", "Message / SMS"),
    ("url", "URL"),
    ("upi", "UPI"),
    ("qr", "QR"),
    ("voice", "Voice"),
    ("screenshot", "Screenshot"),
)
_VERDICTS = ("safe", "suspicious", "scam")


def _date_window(args):
    range_key = (args.get("range") or "30d").strip().lower()
    today = datetime.utcnow().date()
    if range_key == "today":
        start_day = end_day = today
    elif range_key == "7d":
        start_day, end_day = today - timedelta(days=6), today
    elif range_key == "30d":
        start_day, end_day = today - timedelta(days=29), today
    elif range_key == "custom":
        try:
            start_day = date.fromisoformat(args.get("start", ""))
            end_day = date.fromisoformat(args.get("end", ""))
        except (TypeError, ValueError):
            return None, jsonify(error="Custom range requires valid start and end dates"), 400
        if start_day > end_day:
            start_day, end_day = end_day, start_day
    else:
        range_key = "30d"
        start_day, end_day = today - timedelta(days=29), today

    return {
        "range": range_key,
        "start": start_day,
        "end": end_day,
        "start_dt": datetime.combine(start_day, time.min),
        "end_exclusive": datetime.combine(end_day + timedelta(days=1), time.min),
    }, None, None


def _filtered_scans(window):
    return ScanHistory.query.filter(
        ScanHistory.created_at >= window["start_dt"],
        ScanHistory.created_at < window["end_exclusive"],
    )


def _build_overview(args):
    window, error_response, status = _date_window(args)
    if error_response:
        return error_response, status

    scans = _filtered_scans(window)
    total_scans = scans.with_entities(func.count(ScanHistory.id)).scalar() or 0
    verdict_rows = (
        scans.with_entities(ScanHistory.verdict, func.count(ScanHistory.id))
        .group_by(ScanHistory.verdict)
        .all()
    )
    verdict_counts = {verdict: 0 for verdict in _VERDICTS}
    for verdict, count in verdict_rows:
        key = (verdict or "").lower()
        if key in verdict_counts:
            verdict_counts[key] = int(count)

    type_rows = (
        scans.with_entities(ScanHistory.scan_type, func.count(ScanHistory.id))
        .group_by(ScanHistory.scan_type)
        .all()
    )
    raw_type_counts = {(scan_type or "").lower(): int(count) for scan_type, count in type_rows}
    channel_counts = {key: raw_type_counts.get(key, 0) for key, _label in _CHANNELS}
    channel_counts["message"] += raw_type_counts.get("sms", 0) + raw_type_counts.get("text", 0)

    secure_chat_count = scans.filter(ScanHistory.source == "secure-chat").with_entities(
        func.count(ScanHistory.id)
    ).scalar() or 0

    day_rows = (
        scans.with_entities(
            func.date(ScanHistory.created_at),
            ScanHistory.verdict,
            func.count(ScanHistory.id),
        )
        .group_by(func.date(ScanHistory.created_at), ScanHistory.verdict)
        .order_by(func.date(ScanHistory.created_at))
        .all()
    )
    activity_by_day = {}
    for day_value, verdict, count in day_rows:
        day_key = day_value.strftime("%Y-%m-%d") if hasattr(day_value, "strftime") else str(day_value)
        bucket = activity_by_day.setdefault(
            day_key, {"safe": 0, "suspicious": 0, "scam": 0, "total": 0}
        )
        bucket["total"] += int(count)
        verdict_key = (verdict or "").lower()
        if verdict_key in _VERDICTS:
            bucket[verdict_key] += int(count)

    scam_count = verdict_counts["scam"]
    summary = {
        "registeredUsers": User.query.with_entities(func.count(User.id)).scalar() or 0,
        "totalScans": int(total_scans),
        **verdict_counts,
        "scamPercentage": round(scam_count * 100 / total_scans, 1) if total_scans else 0.0,
    }
    channels = [
        {"key": key, "label": label, "count": channel_counts[key]}
        for key, label in _CHANNELS
    ]
    channels.append({"key": "secure-chat", "label": "Secure Chat", "count": int(secure_chat_count)})

    return {
        "filters": {
            "range": window["range"],
            "start": window["start"].isoformat(),
            "end": window["end"].isoformat(),
        },
        "summary": summary,
        "channels": channels,
        "dateActivity": [
            {"date": day_key, **activity}
            for day_key, activity in sorted(activity_by_day.items())
        ],
        "verdictDistribution": verdict_counts,
    }, None


@universal_dashboard_bp.route("/universal-security")
@login_required
def universal_security_page():
    return render_template(
        "universal_security.html",
        active_page="universal-security",
        page_title="Universal Security Dashboard",
        overview_url="/api/universal-security/overview",
    )


@universal_dashboard_bp.route("/api/universal-security/overview")
@login_required
def universal_security_overview_api():
    payload, status = _build_overview(request.args)
    if status:
        return payload, status
    return jsonify(payload)