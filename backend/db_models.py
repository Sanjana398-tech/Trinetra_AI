"""
TRINETRA AI - Database Models
===============================
SQLAlchemy ORM models. SQLite for local/dev, swappable via DATABASE_URL
for production (see backend/config.py).

Tables:
    - users          : registered accounts (auth is wired in a later phase)
    - scan_history    : every scan performed (message / url / qr / voice / screenshot)
    - reports         : generated downloadable report records
    - system_logs     : application/audit event log
"""

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from backend.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scans = db.relationship("ScanHistory", backref="user", lazy=True)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self):
        return f"<User {self.email}>"


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    source = db.Column(db.String(50), default="web", nullable=False)
    external_user_id = db.Column(db.String(150), nullable=True)

    # message | url | qr | voice | screenshot
    scan_type = db.Column(db.String(30), nullable=False, index=True)
    input_summary = db.Column(db.Text, nullable=False)

    # safe | suspicious | scam
    verdict = db.Column(db.String(20), nullable=False, index=True)
    confidence_score = db.Column(db.Float, default=0.0)
    risk_score = db.Column(db.Float, default=0.0)

    explanation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<ScanHistory {self.scan_type}:{self.verdict}>"


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_history.id"), nullable=True)
    file_path = db.Column(db.String(255), nullable=False)
    format = db.Column(db.String(10), default="pdf")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    scan = db.relationship("ScanHistory", backref="report", uselist=False)


class SystemLog(db.Model):
    __tablename__ = "system_logs"

    id = db.Column(db.Integer, primary_key=True)
    # info | warning | error | security
    level = db.Column(db.String(20), default="info", nullable=False)
    message = db.Column(db.String(255), nullable=False)
    source = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<SystemLog {self.level}:{self.message[:30]}>"
