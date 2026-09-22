"""
TRINETRA AI - Test Data Generator
===================================
Populates the dashboard with realistic test scan records for demonstration and testing.

Usage:
    python populate_dashboard.py                 # Generates 30 random scans for demo user
    python populate_dashboard.py --clear         # Clear all scans before generating
    python populate_dashboard.py --count 50      # Generate 50 scans

This creates a demo user (if needed) and generates varied scan records across all
scan types to populate dashboard charts and statistics.
"""

import os
import sys
import random
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault('FLASK_ENV', 'development')

# Suppress warnings from transformers and torch if they're loading
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

try:
    from backend import create_app
    from backend.extensions import db
    from backend.db_models import User, ScanHistory, SystemLog
    from werkzeug.security import generate_password_hash
except ImportError as e:
    print(f"❌ Error importing backend modules: {e}")
    print("\nPlease ensure all dependencies are installed:")
    print("  pip install -r requirements.txt")
    print("  pip install torch transformers")
    sys.exit(1)


# Test data templates
MESSAGE_SAMPLES = [
    ("SMS: 'Your KYC has expired, verify at bit.ly/xyz123'", "scam", 96.4, 92.0),
    ("Email: 'Your Amazon order has shipped'", "safe", 12.1, 8.0),
    ("WhatsApp: 'Are we still meeting at 6pm?'", "safe", 4.0, 2.0),
    ("SMS: 'Click here to claim your lottery prize'", "scam", 89.3, 85.0),
    ("Telegram: 'Let me know when you're free'", "safe", 8.5, 5.0),
    ("SMS: 'Confirm your bank details to proceed'", "scam", 94.2, 91.0),
    ("Email: 'Team standup at 2pm tomorrow'", "safe", 2.1, 1.0),
    ("SMS: 'Congratulations! You've won Rs. 10 lakhs'", "scam", 98.5, 96.0),
    ("WhatsApp: 'Thanks for the documents'", "safe", 3.2, 1.5),
    ("SMS: 'Update payment method immediately'", "suspicious", 72.0, 68.0),
]

URL_SAMPLES = [
    ("http://paytm-rewards-verify.tk/claim", "scam", 91.2, 88.5),
    ("https://www.icicibank.com/personal-banking", "safe", 3.2, 1.5),
    ("https://accounts.google.com/login", "safe", 2.1, 1.0),
    ("http://amazon-refund-process.xyz/claim", "scam", 87.6, 84.0),
    ("https://github.com/trinetra-ai", "safe", 1.5, 0.8),
    ("http://verify-paypal-account-now.tk", "scam", 93.8, 90.0),
    ("https://www.wikipedia.org", "safe", 0.5, 0.2),
    ("http://claim-govt-subsidy-123.xyz", "scam", 95.1, 92.0),
]

QR_SAMPLES = [
    ("QR → upi://pay?pa=fraud@upi&am=4999", "suspicious", 68.0, 61.0),
    ("QR → https://github.com", "safe", 2.0, 1.0),
    ("QR → http://malicious-tracker.xyz/qr123", "scam", 85.2, 81.0),
    ("QR → https://www.google.com", "safe", 1.8, 0.9),
    ("QR → upi://pay?pa=legit@hdfc&am=500", "safe", 5.3, 3.0),
]

SCREENSHOT_SAMPLES = [
    ("Payment screenshot: UPI ref 220098xxxx, amount Rs. 15,000", "suspicious", 54.3, 49.0),
    ("Payment screenshot: Google Pay confirmed, amount Rs. 100", "safe", 8.5, 5.0),
    ("Payment screenshot: NEFT transfer Rs. 2,00,000", "safe", 12.1, 8.0),
    ("Fake payment screen: Amount Rs. 50,000", "scam", 78.9, 75.0),
    ("Payment screenshot: Paytm wallet top-up Rs. 500", "safe", 6.2, 4.0),
]

VOICE_SAMPLES = [
    ("Call transcript: 'This is your bank, share the OTP...'", "scam", 98.1, 95.0),
    ("Call transcript: 'Hello, this is customer support'", "safe", 15.3, 10.0),
    ("Call transcript: 'Verify your account immediately'", "scam", 91.2, 88.0),
    ("Call transcript: 'Thanks for calling, how can I help?'", "safe", 8.7, 5.0),
    ("Call transcript: 'Your package is ready for pickup'", "safe", 12.4, 8.0),
]

UPI_SAMPLES = [
    ("UPI ID: refund-agent-88@okaxis, note: 'GPay refund verify', amount Rs. 10,000", "scam", 95.5, 91.0),
    ("UPI ID: rajesh.kumar@sbi, note: 'Dinner share', amount Rs. 450", "safe", 3.2, 1.5),
    ("UPI ID: cashback-winner-100@okicici, note: 'Congratulations cashback', amount Rs. 4,999", "scam", 98.2, 94.0),
    ("UPI ID: shop@paytmbusiness, note: 'Grocery bill', amount Rs. 1,200", "safe", 2.1, 1.0),
    ("UPI ID: quickloan-support@ybl, note: 'Processing fee', amount Rs. 2,500", "suspicious", 64.0, 58.0),
]


def get_or_create_demo_user():
    """Create or retrieve demo user for testing."""
    demo_email = "demo@trinetra.local"
    user = User.query.filter_by(email=demo_email).first()
    
    if not user:
        user = User(
            full_name="Demo User",
            email=demo_email,
            is_admin=False,
        )
        user.set_password("demo123456")
        db.session.add(user)
        db.session.commit()
        print(f"✓ Created demo user: {demo_email} (password: demo123456)")
    else:
        print(f"✓ Using existing demo user: {demo_email}")
    
    return user


def generate_test_scans(user_id, count=30):
    """Generate random test scan records distributed across all types and dates."""
    all_samples = (
        [("message", *s) for s in MESSAGE_SAMPLES] +
        [("url", *s) for s in URL_SAMPLES] +
        [("qr", *s) for s in QR_SAMPLES] +
        [("screenshot", *s) for s in SCREENSHOT_SAMPLES] +
        [("voice", *s) for s in VOICE_SAMPLES] +
        [("upi", *s) for s in UPI_SAMPLES]
    )
    
    now = datetime.utcnow()
    created_count = 0
    
    for i in range(count):
        # Spread scans across the last 30 days
        days_offset = random.randint(0, 29)
        hours_offset = random.randint(0, 23)
        created_at = now - timedelta(days=days_offset, hours=hours_offset)
        
        scan_type, summary, verdict, confidence, risk = random.choice(all_samples)
        
        scan = ScanHistory(
            user_id=user_id,
            scan_type=scan_type,
            input_summary=summary,
            verdict=verdict,
            confidence_score=confidence,
            risk_score=risk,
            explanation=f"Test scan #{i+1} - {verdict.upper()} detected",
            created_at=created_at,
        )
        db.session.add(scan)
        created_count += 1
    
    db.session.add(SystemLog(
        level="info",
        message=f"Generated {created_count} test scans for dashboard demonstration",
        source="populate_dashboard",
    ))
    db.session.commit()
    
    return created_count


def clear_user_scans(user_id):
    """Delete all scans for a specific user."""
    scan_count = ScanHistory.query.filter_by(user_id=user_id).count()
    if scan_count > 0:
        ScanHistory.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        print(f"✓ Cleared {scan_count} existing scans")
    return scan_count


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate test scan data for the dashboard"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=30,
        help="Number of test scans to generate (default: 30)"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing scans before generating new ones"
    )
    
    args = parser.parse_args()
    
    app = create_app()
    
    with app.app_context():
        print("\n" + "="*60)
        print("TRINETRA AI - Dashboard Test Data Generator")
        print("="*60 + "\n")
        
        # Get or create demo user
        user = get_or_create_demo_user()
        
        # Clear existing scans if requested
        if args.clear:
            clear_user_scans(user.id)
        
        # Generate test scans
        print(f"\nGenerating {args.count} test scan records...")
        count = generate_test_scans(user.id, args.count)
        
        print(f"✓ Successfully created {count} test scans\n")
        print("📊 Dashboard Statistics:")
        
        # Display stats
        scans = ScanHistory.query.filter_by(user_id=user.id).all()
        verdicts = {"safe": 0, "suspicious": 0, "scam": 0}
        types = {}
        
        for scan in scans:
            verdicts[scan.verdict] = verdicts.get(scan.verdict, 0) + 1
            types[scan.scan_type] = types.get(scan.scan_type, 0) + 1
        
        trust_score = round((verdicts["safe"] / len(scans)) * 100, 1) if scans else 0
        
        print(f"  • Total scans: {len(scans)}")
        print(f"  • Safe: {verdicts['safe']} | Suspicious: {verdicts['suspicious']} | Scam: {verdicts['scam']}")
        print(f"  • Trust score: {trust_score}%")
        print(f"  • Scan types: {dict(types)}")
        
        print(f"\n✓ Dashboard is now ready for testing!")
        print(f"✓ Login with: demo@trinetra.local / demo123456")
        print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
