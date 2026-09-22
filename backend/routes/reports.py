"""
TRINETRA AI - Report Generator Routes
=========================================
Lets the user browse scan records and download a PDF report for any
one of them. PDF is generated in-memory (reportlab) and streamed back
— no file is written to disk, so nothing needs cleanup.
"""

from flask import Blueprint, render_template, send_file, abort
from flask_login import login_required, current_user

from backend.db_models import ScanHistory
from backend.utils.report_generator import generate_scan_report_pdf
from backend.utils.scan_visibility import visible_scans_query

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("")
@login_required
def list_reports():
    records = visible_scans_query(current_user).order_by(ScanHistory.created_at.desc()).limit(50).all()
    return render_template(
        "reports/list.html",
        active_page="reports",
        page_title="Report Generator",
        records=records,
    )


@reports_bp.route("/<int:record_id>/download")
@login_required
def download_report(record_id):
    record = visible_scans_query(current_user).filter(ScanHistory.id == record_id).first()
    if record is None:
        abort(404)

    pdf_buffer = generate_scan_report_pdf(record)
    filename = f"trinetra-scan-report-{record.id}.pdf"
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
