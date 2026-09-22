"""
TRINETRA AI - Analytics query helpers
=======================================
Date / type / verdict filtering and SQL aggregations over ScanHistory.
All stats are computed in the database — callers should not load the
full history into Python just to count rows.
"""

from datetime import datetime, timedelta, date
from collections import OrderedDict

from sqlalchemy import func

from backend.db_models import ScanHistory
from backend.utils.channels import CHANNEL_TYPES, channel_label
from backend.utils.scan_visibility import visible_scans_query

VALID_RANGES = ("today", "7d", "30d", "90d", "all", "custom")
VALID_VERDICTS = ("safe", "suspicious", "scam")
RECENT_LIMIT = 15
SUMMARY_TRUNC = 80


def _parse_iso_date(raw):
    if not raw:
        return None
    try:
        return datetime.strptime(raw.strip()[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _start_of_day(d: date) -> datetime:
    return datetime(d.year, d.month, d.day)


def resolve_date_window(args):
    """
    Return (range_key, start_dt, end_dt_exclusive, start_date, end_date).
    end_dt is exclusive so a selected calendar day is fully included.
    """
    range_key = (args.get("range") or "30d").strip().lower()
    if range_key not in VALID_RANGES:
        range_key = "30d"

    today = datetime.utcnow().date()
    start_date = None
    end_date = today

    if range_key == "today":
        start_date = today
    elif range_key == "7d":
        start_date = today - timedelta(days=6)
    elif range_key == "30d":
        start_date = today - timedelta(days=29)
    elif range_key == "90d":
        start_date = today - timedelta(days=89)
    elif range_key == "all":
        start_date = None
        end_date = today
    else:
        start_date = _parse_iso_date(args.get("start"))
        end_date = _parse_iso_date(args.get("end")) or today
        if start_date and end_date and start_date > end_date:
            start_date, end_date = end_date, start_date
        if start_date is None:
            start_date = today - timedelta(days=29)

    start_dt = _start_of_day(start_date) if start_date else None
    end_exclusive = _start_of_day(end_date + timedelta(days=1)) if end_date else None
    return range_key, start_dt, end_exclusive, start_date, end_date


def parse_filters(args):
    range_key, start_dt, end_exclusive, start_date, end_date = resolve_date_window(args)
    scan_type = (args.get("type") or "all").strip().lower()
    verdict = (args.get("verdict") or "all").strip().lower()
    if scan_type != "all" and not scan_type:
        scan_type = "all"
    if verdict not in VALID_VERDICTS:
        verdict = "all"
    return {
        "range": range_key,
        "start": start_dt,
        "end": end_exclusive,
        "start_date": start_date.isoformat() if start_date else None,
        "end_date": end_date.isoformat() if end_date else None,
        "scan_type": scan_type,
        "verdict": verdict,
    }


def filtered_query(user, filters):
    query = visible_scans_query(user)
    if filters["start"] is not None:
        query = query.filter(ScanHistory.created_at >= filters["start"])
    if filters["end"] is not None:
        query = query.filter(ScanHistory.created_at < filters["end"])
    if filters["scan_type"] != "all":
        query = query.filter(ScanHistory.scan_type == filters["scan_type"])
    if filters["verdict"] != "all":
        query = query.filter(ScanHistory.verdict == filters["verdict"])
    return query


def available_types(user):
    """Supported modules, plus any extra scan_type values already stored."""
    rows = (
        visible_scans_query(user)
        .with_entities(ScanHistory.scan_type)
        .distinct()
        .all()
    )
    seen = {row[0] for row in rows if row[0]}
    ordered = list(CHANNEL_TYPES)
    for extra in sorted(seen):
        if extra not in CHANNEL_TYPES:
            ordered.append(extra)
    return [
        {"key": key, "label": channel_label(key)}
        for key in ordered
        if key in CHANNEL_TYPES or key in seen
    ]


def _as_day_str(value):
    if value is None:
        return None
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")
    return str(value)[:10]


def _day_expr():
    return func.date(ScanHistory.created_at)


def _truncate(text, limit=SUMMARY_TRUNC):
    text = " ".join((text or "").split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def _counts_by_verdict(query):
    rows = (
        query.with_entities(ScanHistory.verdict, func.count(ScanHistory.id))
        .group_by(ScanHistory.verdict)
        .all()
    )
    counts = {"safe": 0, "suspicious": 0, "scam": 0}
    for verdict, n in rows:
        key = (verdict or "").lower()
        if key in counts:
            counts[key] = int(n)
        else:
            counts[key] = int(n)
    return counts


def _counts_by_type(query):
    rows = (
        query.with_entities(ScanHistory.scan_type, func.count(ScanHistory.id))
        .group_by(ScanHistory.scan_type)
        .all()
    )
    return {scan_type: int(n) for scan_type, n in rows if scan_type}


def _type_verdict_matrix(query):
    rows = (
        query.with_entities(
            ScanHistory.scan_type,
            ScanHistory.verdict,
            func.count(ScanHistory.id),
        )
        .group_by(ScanHistory.scan_type, ScanHistory.verdict)
        .all()
    )
    data = {}
    for scan_type, verdict, n in rows:
        bucket = data.setdefault(
            scan_type, {"total": 0, "safe": 0, "suspicious": 0, "scam": 0}
        )
        key = (verdict or "").lower()
        bucket["total"] += int(n)
        if key in ("safe", "suspicious", "scam"):
            bucket[key] += int(n)
    return data


def _daterange(start: date, end: date):
    days = []
    cur = start
    while cur <= end:
        days.append(cur)
        cur += timedelta(days=1)
    return days


def _timeline_span(filters, query):
    """Choose a continuous daily window for the charts."""
    if filters["start_date"] and filters["end_date"]:
        start = date.fromisoformat(filters["start_date"])
        end = date.fromisoformat(filters["end_date"])
        if (end - start).days > 180:
            return start, end, "week"
        return start, end, "day"

    bounds = query.with_entities(
        func.min(ScanHistory.created_at), func.max(ScanHistory.created_at)
    ).first()
    if not bounds or not bounds[0]:
        today = datetime.utcnow().date()
        return today - timedelta(days=29), today, "day"
    start = bounds[0].date()
    end = bounds[1].date()
    if (end - start).days > 180:
        return start, end, "week"
    return start, end, "day"


def _bucket_key(created_at, mode):
    if mode == "week":
        iso = created_at.date().isocalendar()
        return f"{iso[0]}-W{iso[1]:02d}"
    return created_at.strftime("%Y-%m-%d")


def _bucket_label(key, mode):
    if mode == "week":
        return key
    dt = datetime.strptime(key, "%Y-%m-%d")
    return dt.strftime("%d %b")


def build_summary(query):
    verdicts = _counts_by_verdict(query)
    total = verdicts.get("safe", 0) + verdicts.get("suspicious", 0) + verdicts.get("scam", 0)
    extra = sum(v for k, v in verdicts.items() if k not in VALID_VERDICTS)
    total += extra
    threats = verdicts.get("suspicious", 0) + verdicts.get("scam", 0)
    detection_rate = round((threats / total) * 100, 1) if total else 0.0

    scam_rows = (
        query.filter(ScanHistory.verdict == "scam")
        .with_entities(ScanHistory.scan_type, func.count(ScanHistory.id))
        .group_by(ScanHistory.scan_type)
        .order_by(func.count(ScanHistory.id).desc())
        .all()
    )
    most = None
    if scam_rows:
        scan_type, n = scam_rows[0]
        most = {"type": scan_type, "label": channel_label(scan_type), "count": int(n)}

    return {
        "total": total,
        "safe": verdicts.get("safe", 0),
        "suspicious": verdicts.get("suspicious", 0),
        "scam": verdicts.get("scam", 0),
        "detectionRate": detection_rate,
        "mostCommonThreat": most,
    }


def build_timeline(query, filters):
    start, end, mode = _timeline_span(filters, query)
    day_expr = _day_expr()
    rows = (
        query.with_entities(day_expr, ScanHistory.verdict, func.count(ScanHistory.id))
        .group_by(day_expr, ScanHistory.verdict)
        .all()
    )

    buckets = OrderedDict()
    if mode == "day":
        for d in _daterange(start, end):
            key = d.isoformat()
            buckets[key] = {"safe": 0, "suspicious": 0, "scam": 0}
    grouped = {}
    for day_val, verdict, n in rows:
        day_str = _as_day_str(day_val)
        if not day_str:
            continue
        if mode == "week":
            dt = datetime.strptime(day_str, "%Y-%m-%d")
            key = _bucket_key(dt, "week")
        else:
            key = day_str
        grouped.setdefault(key, {"safe": 0, "suspicious": 0, "scam": 0})
        vkey = (verdict or "").lower()
        if vkey in grouped[key]:
            grouped[key][vkey] += int(n)
        if mode == "week" and key not in buckets:
            buckets[key] = {"safe": 0, "suspicious": 0, "scam": 0}

    if mode == "week":
        for key in sorted(grouped):
            buckets[key] = grouped[key]
    else:
        for key, vals in grouped.items():
            if key in buckets:
                buckets[key] = vals

    labels, safe, suspicious, scam = [], [], [], []
    for key, vals in buckets.items():
        labels.append(_bucket_label(key, mode))
        safe.append(vals.get("safe", 0))
        suspicious.append(vals.get("suspicious", 0))
        scam.append(vals.get("scam", 0))

    return {
        "granularity": mode,
        "labels": labels,
        "safe": safe,
        "suspicious": suspicious,
        "scam": scam,
        "threats": [s + c for s, c in zip(suspicious, scam)],
    }


def build_by_type(query):
    counts = _counts_by_type(query)
    keys = [k for k in CHANNEL_TYPES if k in counts] + [
        k for k in sorted(counts) if k not in CHANNEL_TYPES
    ]
    # Keep zero channels that are filtered in when showing all types? Only those with data.
    return {
        "keys": keys,
        "labels": [channel_label(k) for k in keys],
        "values": [counts.get(k, 0) for k in keys],
    }


def build_scam_by_type(query):
    rows = (
        query.filter(ScanHistory.verdict == "scam")
        .with_entities(ScanHistory.scan_type, func.count(ScanHistory.id))
        .group_by(ScanHistory.scan_type)
        .all()
    )
    counts = {scan_type: int(n) for scan_type, n in rows if scan_type}
    keys = [k for k in CHANNEL_TYPES if k in counts] + [
        k for k in sorted(counts) if k not in CHANNEL_TYPES
    ]
    return {
        "keys": keys,
        "labels": [channel_label(k) for k in keys],
        "values": [counts.get(k, 0) for k in keys],
    }


def build_type_date(query, filters):
    start, end, mode = _timeline_span(filters, query)
    day_expr = _day_expr()
    type_counts = _counts_by_type(query)
    type_keys = [k for k in CHANNEL_TYPES if k in type_counts] + [
        k for k in sorted(type_counts) if k not in CHANNEL_TYPES
    ]
    if not type_keys:
        return {"dates": [], "types": [], "labels": [], "rows": []}

    rows = (
        query.with_entities(day_expr, ScanHistory.scan_type, func.count(ScanHistory.id))
        .group_by(day_expr, ScanHistory.scan_type)
        .all()
    )

    if mode == "day":
        date_keys = [d.isoformat() for d in _daterange(start, end)]
    else:
        date_keys = []

    matrix_map = {}
    week_order = []
    for day_val, scan_type, n in rows:
        day_str = _as_day_str(day_val)
        if not day_str or not scan_type:
            continue
        if mode == "week":
            dt = datetime.strptime(day_str, "%Y-%m-%d")
            key = _bucket_key(dt, "week")
            if key not in week_order:
                week_order.append(key)
        else:
            key = day_str
        matrix_map.setdefault(key, {})
        matrix_map[key][scan_type] = matrix_map[key].get(scan_type, 0) + int(n)

    if mode == "week":
        date_keys = sorted(set(week_order) | set(matrix_map.keys()))

    matrix = []
    for key in date_keys:
        row = {"date": _bucket_label(key, mode), "key": key}
        for t in type_keys:
            row[t] = matrix_map.get(key, {}).get(t, 0)
        matrix.append(row)

    return {
        "dates": [_bucket_label(k, mode) for k in date_keys],
        "types": type_keys,
        "labels": [channel_label(k) for k in type_keys],
        "rows": matrix,
    }


def build_table(query):
    data = _type_verdict_matrix(query)
    keys = [k for k in CHANNEL_TYPES if k in data] + [
        k for k in sorted(data) if k not in CHANNEL_TYPES
    ]
    rows = []
    for key in keys:
        bucket = data[key]
        total = bucket["total"]
        scam = bucket["scam"]
        rows.append(
            {
                "type": key,
                "label": channel_label(key),
                "total": total,
                "safe": bucket["safe"],
                "suspicious": bucket["suspicious"],
                "scam": scam,
                "scamPct": round((scam / total) * 100, 1) if total else 0.0,
            }
        )
    return rows


def build_recent_threats(query):
    rows = (
        query.filter(ScanHistory.verdict.in_(("suspicious", "scam")))
        .order_by(ScanHistory.created_at.desc())
        .limit(RECENT_LIMIT)
        .all()
    )
    items = []
    for scan in rows:
        items.append(
            {
                "id": scan.id,
                "created_at": scan.created_at.strftime("%d %b %Y, %I:%M %p"),
                "scan_type": scan.scan_type,
                "scan_type_label": channel_label(scan.scan_type),
                "input_summary": _truncate(scan.input_summary),
                "verdict": (scan.verdict or "").lower(),
                "risk_score": round(float(scan.risk_score or 0), 1),
            }
        )
    return items


def build_overview(user, args):
    filters = parse_filters(args)

    def scoped():
        # Fresh Query each time — SQLAlchemy Query is generative, but
        # grouping/with_entities must never leak into a sibling aggregation.
        return filtered_query(user, filters)

    summary = build_summary(scoped())
    timeline = build_timeline(scoped(), filters)
    return {
        "filters": {
            "range": filters["range"],
            "start": filters["start_date"],
            "end": filters["end_date"],
            "type": filters["scan_type"],
            "verdict": filters["verdict"],
        },
        "types": available_types(user),
        "empty": summary["total"] == 0,
        "summary": summary,
        "timeline": timeline,
        "threatTrend": {
            "labels": timeline["labels"],
            "values": timeline["threats"],
        },
        "byType": build_by_type(scoped()),
        "scamByType": build_scam_by_type(scoped()),
        "byVerdict": {
            "safe": summary["safe"],
            "suspicious": summary["suspicious"],
            "scam": summary["scam"],
        },
        "typeDate": build_type_date(scoped(), filters),
        "recentThreats": build_recent_threats(scoped()),
        "table": build_table(scoped()),
    }


def iter_export_rows(user, args):
    filters = parse_filters(args)
    query = filtered_query(user, filters).order_by(ScanHistory.created_at.desc())
    for scan in query.all():
        yield {
            "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": scan.scan_type,
            "scan_type_label": channel_label(scan.scan_type),
            "input_summary": _truncate(scan.input_summary, 200),
            "verdict": (scan.verdict or "").lower(),
            "risk_score": round(float(scan.risk_score or 0), 1),
            "confidence_score": round(float(scan.confidence_score or 0), 1),
        }
