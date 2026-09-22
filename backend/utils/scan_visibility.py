"""
TRINETRA AI - Scan Visibility Helper
========================================
Scopes ScanHistory queries to the current user's own scans. Shared by
the dashboard, history, and reports routes so "visible to this user" is
defined in exactly one place.
"""

from backend.db_models import ScanHistory


def visible_scans_query(user):
    """Return the user's scans plus persisted Secure Chat scans."""
    return ScanHistory.query.filter(
        (ScanHistory.user_id == user.id)
        | (ScanHistory.source == "secure-chat")
    )
