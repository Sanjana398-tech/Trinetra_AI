"""
TRINETRA AI - Dataset Generator
===================================
Generates two labeled CSVs used to train the Phase 3 models:

    datasets/messages_dataset.csv   columns: text,   label (safe|suspicious|scam)
    datasets/urls_dataset.csv       columns: url,    label (safe|suspicious|scam)

These are TEMPLATE-BASED SYNTHETIC datasets (randomized, reproducible
with a fixed seed) rather than scraped/real user data — appropriate
for a final-year project where the goal is demonstrating a working
detection pipeline, not sourcing production training data. Swap this
script's output for a real labeled dataset later without touching any
other file — the training scripts only care about the two CSV columns.

Run:
    python training/generate_datasets.py
"""

import csv
import random
from pathlib import Path

random.seed(42)

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

# =============================================================
# MESSAGE DATASET
# =============================================================

NAMES = ["Ravi", "Priya", "Anjali", "Suresh", "Kavya", "Arjun", "Meera", "Vikram", "Neha", "Rohan"]
BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "PNB", "Kotak Bank"]
COMPANIES = ["Amazon", "Flipkart", "Netflix", "Paytm", "PhonePe", "Zomato", "Swiggy", "IRCTC"]
AMOUNTS = ["Rs. 4,999", "Rs. 12,500", "Rs. 25,000", "Rs. 1,00,000", "$500", "Rs. 799"]
LINKS = ["bit.ly/claim-now", "tinyurl.com/verify-kyc", "secure-update.tk/login",
         "wa.me/919812345678", "shorturl.at/xyzAB", "verify-account.ml/otp"]
PHONES = ["+91 98XXXXXX21", "+91 90XXXXXX45", "1800-XXX-XXXX"]

SCAM_TEMPLATES = [
    "Congratulations {name}! You have WON {amount} in the {company} lucky draw. Claim now at {link} before it expires!",
    "URGENT: Your {bank} account has been suspended due to KYC mismatch. Update immediately at {link} or lose access permanently.",
    "Dear customer, your {bank} debit card will be blocked in 24 hours. Verify your PIN and OTP now at {link}.",
    "Your parcel from {company} is on hold due to unpaid customs fee of {amount}. Pay now at {link} to release it.",
    "ALERT: Suspicious login detected on your account. Share the OTP sent to your number to secure it immediately.",
    "You have been selected for a government loan of {amount} with 0% interest. Apply now, share your Aadhaar and bank details at {link}.",
    "Final notice: Legal action will be taken against you within 24 hours unless you pay the pending fine of {amount} at {link}.",
    "Hi, this is {name} from {bank} support. We need your CVV and OTP to reverse a wrong transaction of {amount} immediately.",
    "Your {company} account earned a free {amount} cashback! Click {link} now, offer expires in 10 minutes.",
    "Job offer: Earn {amount} per day working from home. Send registration fee to this UPI ID to get started today.",
    "Dear user, re-activate your blocked SIM card immediately by sharing the OTP, or your number will be deactivated permanently.",
    "Investment opportunity: Double your money in 7 days! Limited slots, transfer {amount} now at {link}.",
    "Your electricity bill of {amount} is overdue and will be disconnected tonight. Pay instantly at {link} to avoid disconnection.",
    "We tried delivering your {company} parcel but failed. Reschedule and pay a small fee of {amount} at {link}.",
    "CONGRATULATIONS! Your number has won {amount} in the WhatsApp International Lottery. Contact {phone} to claim, share your bank IFSC and account number.",
]

SUSPICIOUS_TEMPLATES = [
    "Dear customer, thank you for banking with {bank}. Limited time offer: get cashback of {amount} on your next transaction, check {link} for details.",
    "Hi {name}, your {company} order is confirmed. As a valued customer, click {link} to unlock an exclusive discount coupon.",
    "Reminder: your {bank} credit card bill of {amount} is due soon. Pay via the {bank} app or visit {link} for more options.",
    "{company} Sale Alert: Flat 70% off ends tonight! Hurry, grab yours before stock runs out at {link}.",
    "Dear valued customer, please update your profile details on {company} to continue enjoying uninterrupted service.",
    "You're pre-approved for a personal loan up to {amount}. Check your eligibility instantly, no obligation, at {link}.",
    "{name}, we noticed unusual activity on your account. If this wasn't you, please review your recent transactions in the app.",
    "Free recharge worth {amount} is waiting for you! Refer 3 friends using {link} to claim your reward.",
    "Your subscription with {company} is about to expire. Renew now at {link} to avoid losing your saved preferences.",
    "Hi, this is a survey from {bank}. Complete it in 2 minutes and get a chance to win {amount}, click {link}.",
]

SAFE_TEMPLATES = [
    "Hi {name}, are we still meeting for lunch tomorrow at 1pm?",
    "Your OTP for login is 482913. Do not share this OTP with anyone. - {bank}",
    "Your {company} order #{amount} has been shipped and will arrive in 2-3 business days.",
    "Reminder: your appointment with Dr. Sharma is scheduled for tomorrow at 5:30 PM.",
    "{name}, don't forget to submit the quarterly report by Friday. Let me know if you need any help.",
    "Payment of {amount} to your {bank} account was successful. Thank you for using our service.",
    "Your {company} cab is arriving in 3 minutes. Driver: Ramesh, vehicle number KA-05-1234.",
    "Hey {name}, happy birthday! Hope you have an amazing day, let's catch up this weekend.",
    "Your electricity bill for this month has been generated. Amount: {amount}, due by the 15th.",
    "Team meeting moved to 4 PM today in conference room B. See you there.",
    "Your {company} delivery was completed today at 2:15 PM. Rate your experience in the app.",
    "Thanks for your feedback {name}, our support team will get back to you within 24 hours.",
    "Your monthly statement from {bank} is now available in the mobile app under Statements.",
    "Reminder: your {company} subscription renews automatically next month at no extra charge.",
    "Good morning! Just checking in — how did the presentation go yesterday?",
]


def _fill(template: str) -> str:
    return template.format(
        name=random.choice(NAMES),
        bank=random.choice(BANKS),
        company=random.choice(COMPANIES),
        amount=random.choice(AMOUNTS),
        link=random.choice(LINKS),
        phone=random.choice(PHONES),
    )


def generate_messages(per_template_variants: int = 12) -> list:
    rows = []
    for label, templates in (("scam", SCAM_TEMPLATES), ("suspicious", SUSPICIOUS_TEMPLATES), ("safe", SAFE_TEMPLATES)):
        for template in templates:
            for _ in range(per_template_variants):
                rows.append((_fill(template), label))
    random.shuffle(rows)
    return rows


def write_messages_csv():
    rows = generate_messages()
    path = DATASETS_DIR / "messages_dataset.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {path}")


# =============================================================
# URL DATASET
# =============================================================

SAFE_DOMAINS = [
    "www.google.com", "www.wikipedia.org", "www.github.com", "www.amazon.in",
    "www.icicibank.com", "www.hdfcbank.com", "www.paytm.com", "www.irctc.co.in",
    "www.linkedin.com", "www.microsoft.com", "www.flipkart.com", "www.netflix.com",
    "www.nptel.ac.in", "www.python.org", "www.stackoverflow.com", "www.geeksforgeeks.org",
]
SAFE_PATHS = ["", "/", "/about", "/products", "/login", "/help", "/account/settings", "/blog/2024/update"]

BRANDS = ["paypal", "amazon", "icicibank", "hdfcbank", "sbi", "paytm", "google", "netflix", "microsoft"]
PHISH_TLDS = ["tk", "ml", "ga", "cf", "xyz", "top", "click", "loan", "win"]
PHISH_KEYWORDS = ["verify", "secure-login", "update-kyc", "confirm-account", "reward-claim", "unlock-account"]

SUSPICIOUS_DOMAINS = [
    "www.dealsbazaar-offers.com", "www.mega-cashback-rewards.com", "www.quickloan-approval.in",
    "www.freegiftcard-winner.com", "www.superdiscount-sale24.com", "www.jobwork-fromhome.in",
]
SUSPICIOUS_PATHS = ["/claim?ref=promo123", "/offer/limited?id=8842", "/survey?bonus=1", "/register?utm_source=sms"]


def _shorten_ip():
    return f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_urls(count_per_class: int = 120) -> list:
    rows = []

    # ---- Safe ----
    for _ in range(count_per_class):
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(SAFE_PATHS)
        rows.append((f"https://{domain}{path}", "safe"))

    # ---- Suspicious (promo/marketing sites: pushy but not overtly malicious structurally) ----
    for _ in range(count_per_class):
        domain = random.choice(SUSPICIOUS_DOMAINS)
        path = random.choice(SUSPICIOUS_PATHS)
        scheme = random.choice(["https", "http"])
        rows.append((f"{scheme}://{domain}{path}", "suspicious"))

    # ---- Scam / phishing ----
    for _ in range(count_per_class):
        pattern = random.randint(0, 4)
        brand = random.choice(BRANDS)
        keyword = random.choice(PHISH_KEYWORDS)
        tld = random.choice(PHISH_TLDS)

        if pattern == 0:
            url = f"http://{_shorten_ip()}/{keyword}/{brand}"
        elif pattern == 1:
            url = f"http://{brand}-{keyword}.{tld}/login"
        elif pattern == 2:
            url = f"http://secure.{brand}.{keyword}-verify.{tld}"
        elif pattern == 3:
            url = f"http://{keyword}.{brand}account-{random.randint(100,999)}.{tld}/index.php?user=login"
        else:
            shortener = random.choice(["bit.ly", "tinyurl.com", "cutt.ly"])
            url = f"http://{shortener}/{brand}{random.randint(1000,9999)}"
        rows.append((url, "scam"))

    random.shuffle(rows)
    return rows


def write_urls_csv():
    rows = generate_urls()
    path = DATASETS_DIR / "urls_dataset.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {path}")


# =============================================================
# UPI DATASET
# =============================================================

UPI_SAFE_NAMES = ["amit", "sunita", "rahul", "priya", "karan", "sneha", "deepak", "neha", "sanjay", "pooja"]
UPI_SAFE_DOMAINS = ["sbi", "okhdfcbank", "okaxis", "okicici", "ybl", "paytm", "apl", "ibl"]
UPI_SAFE_NOTES = ["dinner share", "rent payment", "grocery bill", "electricity payment", "movie tickets", "recharge", "office lunch", "gift", ""]

UPI_SUSPICIOUS_NAMES = ["easy-loans", "megadeals-offers", "cashback-rewards", "survey-bonus", "quickpay-support", "fast-loans"]
UPI_SUSPICIOUS_DOMAINS = ["paytmbusiness", "okbizaxis", "icici", "okaxis"]
UPI_SUSPICIOUS_NOTES = ["promo cashback reward", "limited discount", "survey reward", "special cashback offer", "processing fee", ""]

UPI_SCAM_NAMES = ["lottery-winner-100", "paytm-refund-support", "electricity-disconnection", "double-money-scheme", "sim-verification-agent", "emergency-fine-pay"]
UPI_SCAM_DOMAINS = ["upi", "okbizaxis", "paytmbusiness", "ybl"]
UPI_SCAM_NOTES = ["urgent kyc verification required", "whatsapp international lottery claim", "overdue electricity bill pay now to avoid disconnection", "registration fee for online work from home job", "emergency medical deposit"]

def generate_upi_data(count_per_class: int = 150) -> list:
    rows = []
    
    # ---- Safe ----
    for _ in range(count_per_class):
        name = random.choice(UPI_SAFE_NAMES)
        if random.random() > 0.4:
            name += str(random.randint(1, 999))
        domain = random.choice(UPI_SAFE_DOMAINS)
        upi_id = f"{name}@{domain}"
        amount = random.choice([50, 100, 250, 450, 1200, 3500, 5000, 8000])
        note = random.choice(UPI_SAFE_NOTES)
        rows.append((upi_id, amount, note, "safe"))

    # ---- Suspicious ----
    for _ in range(count_per_class):
        name = random.choice(UPI_SUSPICIOUS_NAMES)
        if random.random() > 0.4:
            name += str(random.randint(100, 999))
        domain = random.choice(UPI_SUSPICIOUS_DOMAINS)
        upi_id = f"{name}@{domain}"
        amount = random.choice([1999, 4999, 999, 799, 1500, 3000])
        note = random.choice(UPI_SUSPICIOUS_NOTES)
        rows.append((upi_id, amount, note, "suspicious"))

    # ---- Scam ----
    for _ in range(count_per_class):
        name = random.choice(UPI_SCAM_NAMES)
        if random.random() > 0.4:
            name += str(random.randint(100, 999))
        domain = random.choice(UPI_SCAM_DOMAINS)
        upi_id = f"{name}@{domain}"
        amount = random.choice([4999, 9999, 12500, 25000, 100000])
        note = random.choice(UPI_SCAM_NOTES)
        rows.append((upi_id, amount, note, "scam"))

    random.shuffle(rows)
    return rows

def write_upi_csv():
    rows = generate_upi_data()
    path = DATASETS_DIR / "upi_dataset.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["upi_id", "amount", "note", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {path}")


if __name__ == "__main__":
    write_messages_csv()
    write_urls_csv()
    write_upi_csv()
