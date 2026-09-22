"""
TRINETRA AI - UPI Feature Extraction
=====================================
Extracts 10 lexical, structural, and semantic features from a UPI ID,
transaction amount, and note, and provides reason explanations and safety tips.
"""

import re

FEATURE_NAMES = [
    "upi_id_length",
    "username_length",
    "num_digits_username",
    "num_special_username",
    "is_known_psp",
    "contains_scam_keyword_username",
    "amount",
    "amount_is_common_scam",
    "note_length",
    "contains_scam_keyword_note",
]

KNOWN_UPI_SUFFIXES = {
    "axl", "sbi", "icici", "hdfcbank", "axisbank", "upi", "yesbank", "okbizaxis",
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "paytm", "apl", "ibl",
    "waaxis", "wasbi", "wahdfcbank", "waicici", "barodampay", "kmbl", "paytmbusiness",
    "okhdfc", "okicici", "oksbi", "okaxis"
}

SCAM_KEYWORDS = {
    "cashback", "win", "lucky", "lottery", "prize", "gift", "support", "refund",
    "help", "bonus", "loan", "verify", "kyc", "customer", "care", "double", "money",
    "reward", "award", "claim", "free", "urgent", "suspend", "block", "electric", "bill",
    "whatsapp", "phonepe", "paytm", "gpay", "verification", "official"
}

COMMON_SCAM_AMOUNTS = {4999.0, 9999.0, 12500.0, 25000.0, 50000.0, 100000.0}
UPI_ID_RE = re.compile(r"^[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,20}$")


def is_valid_upi_id(upi_id):
    """Return whether a value has the supported UPI VPA shape."""
    return bool(UPI_ID_RE.fullmatch(str(upi_id or "").strip()))


def extract_upi_features(upi_id, amount=0.0, note=""):
    """
    Extract 10 structural features from the VPA, amount, and note.
    """
    upi_id = str(upi_id).strip().lower()
    note = str(note).strip().lower()
    try:
        amount_val = float(amount or 0.0)
    except ValueError:
        amount_val = 0.0

    # Parse UPI ID: username@psp
    if "@" in upi_id:
        username, psp = upi_id.split("@", 1)
    else:
        username = upi_id
        psp = ""

    upi_id_length = len(upi_id)
    username_length = len(username)
    num_digits_username = sum(c.isdigit() for c in username)
    num_special_username = sum(c in ".-_" for c in username)
    
    is_known_psp = 1 if psp in KNOWN_UPI_SUFFIXES else 0
    contains_scam_keyword_username = sum(1 for kw in SCAM_KEYWORDS if kw in username)

    amount_is_common_scam = 0
    if amount_val in COMMON_SCAM_AMOUNTS:
        amount_is_common_scam = 1
    elif amount_val > 0:
        str_amount = str(int(amount_val))
        if str_amount.endswith(("99", "499", "999")):
            amount_is_common_scam = 1

    note_length = len(note)
    contains_scam_keyword_note = sum(1 for kw in SCAM_KEYWORDS if kw in note)

    return {
        "upi_id_length": upi_id_length,
        "username_length": username_length,
        "num_digits_username": num_digits_username,
        "num_special_username": num_special_username,
        "is_known_psp": is_known_psp,
        "contains_scam_keyword_username": contains_scam_keyword_username,
        "amount": amount_val,
        "amount_is_common_scam": amount_is_common_scam,
        "note_length": note_length,
        "contains_scam_keyword_note": contains_scam_keyword_note,
    }


def feature_vector(upi_id, amount=0.0, note=""):
    """
    Generate an ordered list of features matching FEATURE_NAMES.
    """
    features = extract_upi_features(upi_id, amount, note)
    return [features[name] for name in FEATURE_NAMES]


def explain_reasons(upi_id, amount=0.0, note=""):
    """
    Provide plain-English reasons for the scan score/verdict.
    """
    features = extract_upi_features(upi_id, amount, note)
    reasons = []
    
    if "@" not in upi_id:
        reasons.append("The input UPI ID is invalid because it does not contain an '@' symbol.")
    else:
        username, psp = upi_id.split("@", 1)
        if features["is_known_psp"] == 0:
            reasons.append(f"Uses an unrecognized or uncommon PSP handle prefix/suffix '@{psp}'.")
        if features["contains_scam_keyword_username"] > 0:
            reasons.append("The UPI username contains suspicious scam-related words (e.g., cashback, help, support, win).")
        if features["num_digits_username"] >= 4:
            reasons.append("The UPI username contains an unusually high count of digits, which is typical for auto-generated scam accounts.")
        if features["username_length"] > 25:
            reasons.append("The UPI username is unusually long, which may be trying to mimic a legitimate organization name.")

    if features["amount_is_common_scam"] == 1:
        reasons.append(f"The transaction amount (Rs. {features['amount']}) is a typical figure used in lottery, prize, or processing fee scams.")

    if features["contains_scam_keyword_note"] > 0:
        reasons.append("The transaction note contains high-risk keywords associated with banking fraud, verification requests, or lottery winnings.")
    if features["note_length"] > 100:
        reasons.append("The transaction note is long, often used to create a false sense of urgency or insert confusing instructions.")

    if not reasons:
        reasons.append("No obvious structural or textual warning signs were detected in this UPI request.")

    return reasons


def safety_tips(verdict):
    """
    Provide verdict-appropriate recommendations.
    """
    verdict = str(verdict).lower()
    common = [
        "Double-check the receiver's name displayed in your UPI app before completing any payment.",
        "Remember: you never need to enter your UPI PIN to RECEIVE money. A request asking for your PIN is always a scam.",
    ]
    if verdict == "safe":
        return [
            "The UPI ID and transaction details do not show typical scam patterns. You may proceed with caution.",
        ] + common
    if verdict == "suspicious":
        return [
            "Verify the identity of the recipient through a separate, trusted channel before transferring money.",
            "Do not pay if you are feeling pressured by time limit warnings in the note or request.",
        ] + common
    return [
        "DO NOT send any money or share any OTP/PIN with this recipient.",
        "Report the UPI ID/VPA as spam or fraud directly inside your UPI app.",
        "Block the sender's number and delete the request to prevent future contact.",
    ] + common
