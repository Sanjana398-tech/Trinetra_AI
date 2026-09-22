"""
TRINETRA AI - URL Feature Extraction

The SAME 26 lexical/structural features used during
XGBoost training in Google Colab.

IMPORTANT:
Do not change the feature names or order because the
trained XGBoost model expects these exact 26 features.
"""

import re
from urllib.parse import urlparse


# ============================================================
# EXACT FEATURE ORDER USED DURING XGBOOST TRAINING
# ============================================================

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question",
    "num_equals",
    "num_ampersands",
    "num_at",
    "num_percent",
    "num_digits",
    "num_letters",
    "num_special",
    "has_https",
    "has_http",
    "has_ip",
    "num_domain_parts",
    "num_subdomains",
    "has_at_symbol",
    "has_double_slash",
    "has_shortener",
    "suspicious_keyword_count",
    "https_with_ip",
]


# ============================================================
# URL SHORTENERS
# ============================================================

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "qrco.de",
    "q-r.to",
]


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "signin",
    "password",
    "credential",
    "bank",
    "payment",
    "wallet",
    "otp",
    "claim",
    "reward",
    "prize",
    "free",
    "bonus",
    "gift",
    "alert",
    "suspended",
    "unlock",
]


# ============================================================
# IP ADDRESS PATTERN
# ============================================================

IP_PATTERN = r"^(?:\d{1,3}\.){3}\d{1,3}$"


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):
    """
    Extract the exact 26 features used during XGBoost training.

    Returns:
        dict containing exactly the 26 expected features.
    """

    url = str(url).strip()

    # --------------------------------------------------------
    # PARSE URL
    # --------------------------------------------------------

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    if parsed:
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    else:
        domain = ""
        path = ""
        query = ""

    # --------------------------------------------------------
    # REMOVE USERNAME/PASSWORD FROM DOMAIN
    # --------------------------------------------------------

    domain_without_auth = domain.split("@")[-1]

    # --------------------------------------------------------
    # BASIC LENGTH FEATURES
    # --------------------------------------------------------

    url_length = len(url)
    domain_length = len(domain_without_auth)
    path_length = len(path)
    query_length = len(query)

    # --------------------------------------------------------
    # CHARACTER FEATURES
    # --------------------------------------------------------

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_question = url.count("?")
    num_equals = url.count("=")
    num_ampersands = url.count("&")
    num_at = url.count("@")
    num_percent = url.count("%")

    num_digits = sum(
        c.isdigit()
        for c in url
    )

    num_letters = sum(
        c.isalpha()
        for c in url
    )

    num_special = sum(
        not c.isalnum()
        for c in url
    )

    # --------------------------------------------------------
    # HTTP / HTTPS
    # --------------------------------------------------------

    has_https = int(
        url.lower().startswith("https")
    )

    has_http = int(
        url.lower().startswith("http://")
    )

    # --------------------------------------------------------
    # HOSTNAME
    # --------------------------------------------------------

    hostname = domain_without_auth.split(":")[0]

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    has_ip = int(
        re.match(
            IP_PATTERN,
            hostname
        ) is not None
    )

    # --------------------------------------------------------
    # DOMAIN PARTS
    # --------------------------------------------------------

    if hostname:
        domain_parts = hostname.split(".")
    else:
        domain_parts = []

    num_domain_parts = len(domain_parts)

    num_subdomains = max(
        0,
        len(domain_parts) - 2
    )

    # --------------------------------------------------------
    # SUSPICIOUS SYMBOLS
    # --------------------------------------------------------

    has_at_symbol = int(
        "@" in url
    )

    # Ignore the normal // after http:// or https://
    has_double_slash = int(
        "//" in url[8:]
    )

    # --------------------------------------------------------
    # URL SHORTENER
    # --------------------------------------------------------

    has_shortener = int(
        any(
            domain_name in hostname
            for domain_name in SHORTENER_DOMAINS
        )
    )

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    url_lower = url.lower()

    suspicious_keyword_count = sum(
        keyword in url_lower
        for keyword in SUSPICIOUS_KEYWORDS
    )

    # --------------------------------------------------------
    # HTTPS + IP COMBINATION
    # --------------------------------------------------------

    https_with_ip = int(
        has_https and has_ip
    )

    # --------------------------------------------------------
    # RETURN EXACT 26 FEATURES
    # --------------------------------------------------------

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,

        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,

        "num_question": num_question,
        "num_equals": num_equals,
        "num_ampersands": num_ampersands,
        "num_at": num_at,
        "num_percent": num_percent,

        "num_digits": num_digits,
        "num_letters": num_letters,
        "num_special": num_special,

        "has_https": has_https,
        "has_http": has_http,
        "has_ip": has_ip,

        "num_domain_parts": num_domain_parts,
        "num_subdomains": num_subdomains,

        "has_at_symbol": has_at_symbol,
        "has_double_slash": has_double_slash,

        "has_shortener": has_shortener,

        "suspicious_keyword_count":
            suspicious_keyword_count,

        "https_with_ip": https_with_ip,
    }


# ============================================================
# FEATURE VECTOR
# ============================================================

def feature_vector(url):
    """
    Convert URL features into the exact ordered list
    expected by the trained XGBoost model.
    """

    features = extract_url_features(url)

    return [
        features[name]
        for name in FEATURE_NAMES
    ]


# ============================================================
# EXPLANATIONS AND SAFETY TIPS
# ============================================================

def find_url_in_text(text):
    """Return the first URL found in decoded QR text, or ``None``."""

    if not text:
        return None

    match = re.search(
        r"(?i)\b(?:https?://|www\.)[^\s<>\"']+",
        str(text),
    )

    if not match:
        return None

    return match.group(0).rstrip(".,;:!?)]}")

def explain_reasons(url):
    """Return plain-English reasons based on the extracted URL signals."""

    features = extract_url_features(url)
    reasons = []

    if features["has_ip"]:
        reasons.append("Uses a numeric IP address instead of a recognizable domain name.")
    if features["has_at_symbol"]:
        reasons.append("Contains an @ symbol, which can hide the destination domain.")
    if features["has_shortener"]:
        reasons.append("Uses a URL shortener, so the final destination is hidden.")
    if features["https_with_ip"]:
        reasons.append("Uses HTTPS with an IP address; encryption does not make the destination trustworthy.")
    if features["num_subdomains"] >= 2:
        reasons.append("Contains several subdomains, which can make an untrusted domain look legitimate.")
    if features["suspicious_keyword_count"]:
        reasons.append("Contains words commonly used in phishing links, such as login, verify, or account.")
    if features["url_length"] >= 100:
        reasons.append("Is unusually long, which can indicate tracking or an obscured destination.")
    if features["has_double_slash"]:
        reasons.append("Contains an extra double slash that may be used to obscure part of the URL.")

    if not reasons:
        reasons.append("No common structural warning signs were detected in this URL.")

    return reasons


def safety_tips(verdict):
    """Return verdict-appropriate recommendations for handling a URL."""

    verdict = str(verdict).lower()
    common = [
        "Check the domain carefully before entering passwords, payment details, or OTPs.",
        "When in doubt, open the organization's official app or website directly instead of using the link.",
    ]

    if verdict == "safe":
        return [
            "The URL shows no common phishing indicators, but remain cautious with unexpected links.",
        ] + common
    if verdict == "suspicious":
        return [
            "Do not open the link or enter personal details until the destination has been independently verified.",
            "Ask the sender to confirm the link through a trusted communication channel.",
        ] + common
    return [
        "Do not open the link, download files from it, or reply to the sender.",
        "If you entered credentials, change them from the official website and enable multi-factor authentication.",
        "Report the link as phishing and delete the message.",
    ] + common