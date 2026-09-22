"""
TRINETRA AI - Message Explanation Engine
============================================
The ML model gives a verdict + confidence, but a raw probability isn't
useful to explain "why" to an end user. This module scans the raw text
for known scam-language categories and turns matches into plain-English
reasons — used alongside (not instead of) the ML prediction.
"""

import re

_CATEGORIES = [
    ("Urgency / pressure tactics",
     r"\b(urgent|immediately|act now|right away|expire[sd]?|within\s+\d+\s*(hours?|minutes?)|last chance|final notice)\b",
     "Uses urgency or pressure language to rush you into acting without thinking."),
    ("Prize / lottery bait",
     r"\b(won|winner|lottery|prize|jackpot|congratulations|selected|lucky draw|giveaway)\b",
     "Claims you've won a prize or lottery — a classic scam hook."),
    ("Payment / financial request",
     r"\b(otp|cvv|pin\b|upi\s*id|bank\s*account|debit card|credit card|net\s*banking|transfer\s+money|pay\s*(now|immediately))\b",
     "Requests sensitive financial details (OTP/PIN/card/bank info) that legitimate services never ask for over message."),
    ("KYC / account impersonation",
     r"\b(kyc|verify\s+your\s+account|account\s+(suspend|block|lock)ed?|update\s+your\s+(details|kyc|account)|re-?activate)\b",
     "Impersonates a bank/service asking you to 'verify' or 'update' account details."),
    ("Suspicious link",
     r"(linkurl|https?://|bit\.ly|tinyurl|wa\.me/\d)",
     "Contains a link — always check the actual domain before clicking."),
    ("Threat of legal/account action",
     r"\b(legal action|penalty|fine|arrest|court|police|blocked permanently|deactivat)\w*\b",
     "Threatens a legal or account-loss consequence to intimidate you into responding."),
    ("Too-good-to-be-true offer",
     r"\b(free\s+(gift|recharge|cashback)|100% (free|guaranteed)|risk[- ]free|double\s+your)\b",
     "Offers something free or too-good-to-be-true in exchange for personal information."),
    ("Impersonal greeting / mass message",
     r"\b(dear (customer|user|sir/madam)|valued customer)\b",
     "Uses a generic greeting instead of your name, typical of mass-sent scam blasts."),
]


def generate_reasons(raw_text: str, verdict: str, confidence: float) -> list:
    """
    Scan raw_text for known scam-language patterns and return a list of
    plain-English reasons. Always includes the ML model's own confidence
    statement first, so the explanation reads as one coherent narrative.
    """
    text = raw_text or ""
    reasons = []

    verdict_phrase = {
        "scam": "the language pattern strongly matches known scam messages",
        "suspicious": "some elements resemble scam language, though it isn't conclusive",
        "safe": "the language does not match common scam patterns",
    }.get(verdict, "the model analyzed the message")

    reasons.append(f"The AI model is {confidence:.1f}% confident that {verdict_phrase}.")

    for _label, pattern, explanation in _CATEGORIES:
        if re.search(pattern, text, re.IGNORECASE):
            reasons.append(explanation)

    if len(reasons) == 1 and verdict != "safe":
        reasons.append("The overall wording and structure statistically resembles scam messages the model was trained on.")

    return reasons


def safety_tips(verdict: str) -> list:
    """Static, verdict-appropriate cybersecurity recommendations."""
    common = [
        "Never share OTPs, PINs, CVVs, or passwords with anyone, even if they claim to be your bank.",
        "Verify suspicious requests by contacting the organization directly via their official app or number.",
    ]
    if verdict == "safe":
        return [
            "This message shows no common scam indicators, but always stay cautious with unexpected requests.",
        ] + common
    if verdict == "suspicious":
        return [
            "Don't click any links or reply with personal details until you've verified the sender.",
            "Search online for the exact wording — scam templates are often reused and reported.",
        ] + common
    return [
        "Do not click any links, call any numbers, or reply to this message.",
        "Block and report the sender through your messaging app.",
        "If you already shared details, contact your bank immediately to secure your account.",
    ] + common
