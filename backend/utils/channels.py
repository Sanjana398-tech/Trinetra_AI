"""
Canonical scan-channel keys and display labels.

Kept in one place so the dashboard, history, and analytics pages stay aligned.
"""

CHANNEL_TYPES = ("message", "url", "qr", "voice", "screenshot", "upi")
CHANNEL_LABELS = {
    "message": "Message",
    "url": "URL",
    "qr": "QR",
    "voice": "Voice",
    "screenshot": "Payment",
    "upi": "UPI Scan",
}


def channel_label(scan_type: str) -> str:
    if not scan_type:
        return "Unknown"
    return CHANNEL_LABELS.get(scan_type, scan_type.replace("_", " ").title())
