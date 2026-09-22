"""
TRINETRA AI - Scan History Routes
====================================
Full CRUD over ScanHistory records, scoped to the logged-in user
(see backend/utils/scan_visibility.py).

Routes:
    GET  /history                 list, search, filter, paginate
    GET  /history/new             new-record form
    POST /history/new             create
    GET  /history/<id>            detail view
    GET  /history/<id>/edit       edit form
    POST /history/<id>/edit       update
    POST /history/<id>/delete     delete
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from backend.extensions import db
from backend.db_models import ScanHistory, SystemLog
from backend.utils.scan_visibility import visible_scans_query

history_bp = Blueprint("history", __name__, url_prefix="/history")

VALID_TYPES = ("message", "url", "qr", "voice", "screenshot", "upi")
VALID_VERDICTS = ("safe", "suspicious", "scam")
PER_PAGE = 10


def _log(level, message, source="history"):
    db.session.add(SystemLog(level=level, message=message, source=source))


def _get_visible_or_404(record_id):
    """Fetch a record the current user is allowed to see (own + unowned demo rows), or 404."""
    record = visible_scans_query(current_user).filter(ScanHistory.id == record_id).first()
    if record is None:
        abort(404)
    return record


def _validate_form(form):
    """Validate a submitted scan-record form. Returns (data, errors)."""
    errors = {}

    scan_type = (form.get("scan_type") or "").strip().lower()
    if scan_type not in VALID_TYPES:
        errors["scan_type"] = "Choose a valid channel."

    verdict = (form.get("verdict") or "").strip().lower()
    if verdict not in VALID_VERDICTS:
        errors["verdict"] = "Choose a valid verdict."

    input_summary = (form.get("input_summary") or "").strip()
    if not input_summary:
        errors["input_summary"] = "This field is required."
    elif len(input_summary) > 2000:
        errors["input_summary"] = "Keep it under 2000 characters."

    def _parse_score(name, label):
        raw = (form.get(name) or "").strip()
        if raw == "":
            return 0.0
        try:
            value = float(raw)
        except ValueError:
            errors[name] = f"{label} must be a number."
            return 0.0
        if not (0 <= value <= 100):
            errors[name] = f"{label} must be between 0 and 100."
        return value

    confidence_score = _parse_score("confidence_score", "Confidence")
    risk_score = _parse_score("risk_score", "Risk score")

    explanation = (form.get("explanation") or "").strip()
    if len(explanation) > 2000:
        errors["explanation"] = "Keep it under 2000 characters."

    data = {
        "scan_type": scan_type,
        "verdict": verdict,
        "input_summary": input_summary,
        "confidence_score": confidence_score,
        "risk_score": risk_score,
        "explanation": explanation,
    }
    return data, errors


@history_bp.route("")
@login_required
def list_history():
    q = (request.args.get("q") or "").strip()
    scan_type = request.args.get("type", "all")
    verdict = request.args.get("verdict", "all")
    page = request.args.get("page", 1, type=int)

    query = visible_scans_query(current_user)

    if q:
        query = query.filter(ScanHistory.input_summary.ilike(f"%{q}%"))
    if scan_type in VALID_TYPES:
        query = query.filter(ScanHistory.scan_type == scan_type)
    if verdict in VALID_VERDICTS:
        query = query.filter(ScanHistory.verdict == verdict)

    query = query.order_by(ScanHistory.created_at.desc())
    pagination = query.paginate(page=page, per_page=PER_PAGE, error_out=False)

    return render_template(
        "history/list.html",
        active_page="history",
        page_title="Scan History",
        pagination=pagination,
        records=pagination.items,
        q=q,
        scan_type=scan_type,
        verdict=verdict,
        total_count=visible_scans_query(current_user).count(),
    )


@history_bp.route("/new", methods=["GET", "POST"])
@login_required
def new_record():
    if request.method == "POST":
        data, errors = _validate_form(request.form)
        if errors:
            flash("Please fix the highlighted fields.", "error")
            return render_template(
                "history/form.html",
                active_page="history",
                page_title="Log a Scan",
                mode="create",
                record=data,
                errors=errors,
            )

        record = ScanHistory(user_id=current_user.id, **data)
        db.session.add(record)
        _log("info", f"Manually logged a {data['scan_type']} scan ({data['verdict']}).")
        db.session.commit()
        flash("Scan record created.", "success")
        return redirect(url_for("history.view_record", record_id=record.id))

    return render_template(
        "history/form.html",
        active_page="history",
        page_title="Log a Scan",
        mode="create",
        record={},
        errors={},
    )


@history_bp.route("/<int:record_id>")
@login_required
def view_record(record_id):
    record = _get_visible_or_404(record_id)
    return render_template(
        "history/detail.html",
        active_page="history",
        page_title="Scan Detail",
        record=record,
    )


@history_bp.route("/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
def edit_record(record_id):
    record = _get_visible_or_404(record_id)

    if request.method == "POST":
        data, errors = _validate_form(request.form)
        if errors:
            flash("Please fix the highlighted fields.", "error")
            merged = {**data, "id": record.id}
            return render_template(
                "history/form.html",
                active_page="history",
                page_title="Edit Scan",
                mode="edit",
                record=merged,
                errors=errors,
            )

        for key, value in data.items():
            setattr(record, key, value)
        _log("info", f"Edited scan record #{record.id}.")
        db.session.commit()
        flash("Scan record updated.", "success")
        return redirect(url_for("history.view_record", record_id=record.id))

    return render_template(
        "history/form.html",
        active_page="history",
        page_title="Edit Scan",
        mode="edit",
        record=record,
        errors={},
    )


@history_bp.route("/<int:record_id>/delete", methods=["POST"])
@login_required
def delete_record(record_id):
    record = _get_visible_or_404(record_id)
    db.session.delete(record)
    _log("warning", f"Deleted scan record #{record_id}.")
    db.session.commit()
    flash("Scan record deleted.", "success")
    return redirect(url_for("history.list_history"))
