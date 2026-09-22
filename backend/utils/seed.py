"""
TRINETRA AI - Demo Data Seeder
================================
Optional demo rows for empty-install previews. Seeding is OFF by default
so the dashboard reflects real ScanHistory only. Enable with SEED_DEMO=1.

Also provides a one-time purge of legacy unowned (user_id IS NULL) demo
rows left over from earlier Phase 1 installs.
"""

from datetime import datetime, timedelta
import os
import random

from backend.extensions import db
from backend.db_models import Report, ScanHistory, SystemLog

_DEMO_ROWS = [
    ("message", "SMS: 'Your KYC has expired, update immediately at bit.ly/xyz...'", "scam", 96.4, 92.0),
    ("url", "http://paytm-rewards-verify.tk/claim", "scam", 91.2, 88.5),
    ("message", "Email: 'Your Amazon order #4471 has shipped'", "safe", 12.1, 8.0),
    ("qr", "QR decoded -> upi://pay?pa=fraud@upi&am=4999", "suspicious", 68.0, 61.0),
    ("screenshot", "Payment screenshot: UPI ref 220098xxxx, amount Rs. 15,000", "suspicious", 54.3, 49.0),
    ("voice", "Call transcript: 'This is your bank, share the OTP to verify...'", "scam", 98.1, 95.0),
    ("message", "WhatsApp: 'Hey, are we still meeting at 6?'", "safe", 4.0, 2.0),
    ("url", "https://www.icicibank.com/personal-banking", "safe", 3.2, 1.5),
    ("upi", "UPI ID: cashback-winner-100@okicici, note: 'GPay lucky draw', amount Rs. 4,999", "scam", 98.2, 94.0),
]

_DEMO_EXPLANATION = "Demo record seeded for dashboard preview (Phase 1)."


def purge_demo_scans() -> int:
    """
    Delete only Phase-1 demo ScanHistory rows. Real Secure Chat scans may
    intentionally be unowned because they arrive server-to-server.
    """
    demo_rows = ScanHistory.query.filter(
        ScanHistory.explanation == _DEMO_EXPLANATION
    ).all()
    if not demo_rows:
        return 0

    count = len(demo_rows)
    demo_ids = [row.id for row in demo_rows]
    # Clear dependent report rows first (FK -> scan_history.id).
    Report.query.filter(Report.scan_id.in_(demo_ids)).delete(synchronize_session=False)
    for row in demo_rows:
        db.session.delete(row)
    db.session.add(
        SystemLog(
            level="info",
            message=f"Purged {count} demo ScanHistory row(s) for live dashboard.",
            source="seed",
        )
    )
    db.session.commit()
    return count


def seed_demo_data() -> None:
    """Insert demo rows only when SEED_DEMO=1 and the table is empty."""
    if os.environ.get("SEED_DEMO", "").strip() not in ("1", "true", "True", "yes"):
        return
    if ScanHistory.query.first() is not None:
        return

    now = datetime.utcnow()
    for i, (scan_type, summary, verdict, confidence, risk) in enumerate(_DEMO_ROWS):
        row = ScanHistory(
            scan_type=scan_type,
            input_summary=summary,
            verdict=verdict,
            confidence_score=confidence,
            risk_score=risk,
            explanation=_DEMO_EXPLANATION,
            created_at=now - timedelta(hours=i * 3 + random.randint(0, 2)),
        )
        db.session.add(row)

    db.session.add(
        SystemLog(level="info", message="Demo dataset seeded for dashboard preview.", source="seed")
    )
    db.session.commit()
