"""
TRINETRA AI - Voice Scam Explanation Engine
===============================================
Same approach as message_reasons.py but tuned for phone-call transcripts.
The ML model (DistilBERT trained on scam language) gives the verdict;
this module adds plain-English reasons derived from what was actually
said in the call, plus voice-specific safety tips.
"""

import re

# ---------------------------------------------------------------------------
# Pattern categories specific to voice / phone scams
# ---------------------------------------------------------------------------

_VOICE_CATEGORIES = [
    (
        "Urgency / pressure tactics",
        r"\b(urgent|immediately|right now|act now|right away|expire[sd]?|"
        r"within\s+\d+\s*(hours?|minutes?)|last chance|final notice|don'?t\s+hang\s+up)\b",
        "The caller uses urgency or high-pressure language to prevent you from "
        "thinking clearly or consulting someone else.",
    ),
    (
        "Impersonation of authority",
        r"\b(police|cbi| narcotics|income\s+tax|enforcement|officer|rrb|trai|"
        r"cyber\s+crime|government|ministry|rbi|sebi|nabard|customs|arrest\s+warrant|"
        r"court\s+order|legal\s+notice)\b",
        "The caller claims to be a government official, law enforcement, or regulator — "
        "a common social engineering tactic to intimidate and coerce.",
    ),
    (
        "Bank / OTP / financial request",
        r"\b(otp|one.?time.?password|cvv|pin\b|upi\s*(id|pin)?|bank\s*account|"
        r"debit\s*card|credit\s*card|net\s*banking|transfer|deposit|send\s+money|"
        r"pay\s*(now|immediately)|wallet|atm\s*card)\b",
        "The caller asks for financial credentials or payment — legitimate banks and "
        "government bodies never do this over the phone.",
    ),
    (
        "KYC / account suspension threat",
        r"\b(kyc|verify\s+your\s+account|account\s+(suspend|block|lock|freez)ed?|"
        r"update\s+your\s+(details|kyc|account)|re-?activat|sim\s+(block|suspend))\b",
        "Claims your account or SIM will be suspended unless you provide information — "
        "a scripted pretext used in phone fraud.",
    ),
    (
        "Remote access / screen share request",
        r"\b(anydesk|teamviewer|quick\s*support|screen\s*share|remote\s*(access|control|"
        r"session)|install\s+(an?\s+)?app|download\s+this|open\s+the\s+link)\b",
        "Asks you to install remote-access software, which would give the scammer "
        "full control of your device and accounts.",
    ),
    (
        "Prize / reward bait",
        r"\b(won|winner|lottery|prize|jackpot|congratulations|lucky\s+draw|"
        r"selected|cashback|reward|bonus|refund\s+(due|pending))\b",
        "Offers an unexpected prize or refund to lure you into sharing personal details.",
    ),
    (
        "Threat of arrest / legal action",
        r"\b(arrest|arrested|jail|prison|warrant|court|penalty|fine|case\s+(filed|register)|"
        r"fir|summons|convicted|criminal\s+charges|deport)\b",
        "Threatens arrest, a court case, or deportation to frighten you into complying immediately.",
    ),
    (
        "Secrecy / don't tell anyone",
        r"\b(don'?t\s+tell|keep\s+(this\s+)?secret|confidential|don'?t\s+inform|"
        r"do\s+not\s+share\s+this|between\s+us|nobody\s+should\s+know)\b",
        "Instructs you to keep the call secret — a classic sign of social engineering "
        "designed to isolate you from people who might warn you.",
    ),
    (
        "Personal info fishing",
        r"\b(aadhaar|pan\s*card|passport|date\s+of\s+birth|mother'?s?\s+name|"
        r"full\s+name|residential\s+address|email\s*(id|address))\b",
        "Solicits personally identifiable information that can be used for identity theft.",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_reasons(transcript: str, verdict: str, confidence: float) -> list:
    """
    Scan the call transcript for known voice-scam language patterns and
    return plain-English reasons. Always starts with the model's confidence
    statement so the explanation reads as a coherent narrative.
    """
    text = transcript or ""
    reasons = []

    verdict_phrase = {
        "scam": "the language in this call strongly matches known phone scam scripts",
        "suspicious": "some elements of this call resemble phone scam language, though it isn't conclusive",
        "safe": "the language in this call does not match common phone scam patterns",
    }.get(verdict, "the model analyzed the call transcript")

    reasons.append(
        f"The AI model is {confidence:.1f}% confident that {verdict_phrase}."
    )

    for _label, pattern, explanation in _VOICE_CATEGORIES:
        if re.search(pattern, text, re.IGNORECASE):
            reasons.append(explanation)

    # Fallback if no specific pattern fired but the model flagged it
    if len(reasons) == 1 and verdict != "safe":
        reasons.append(
            "The overall wording and conversational structure statistically "
            "resembles phone scam scripts the model was trained on."
        )

    return reasons


def safety_tips(verdict: str) -> list:
    """Verdict-appropriate safety tips written for phone-call context."""
    common = [
        "Never share OTPs, PINs, Aadhaar/PAN numbers, or bank details over a phone call.",
        "Hang up and call the organization back using the official number from their website or the back of your card.",
    ]
    if verdict == "safe":
        return [
            "This call shows no common scam indicators, but stay alert — "
            "scammers can sound very professional.",
        ] + common
    if verdict == "suspicious":
        return [
            "Do not act on anything the caller asked until you independently verify who they are.",
            "Search online for the caller's number or exact phrases used — scam scripts are widely reported.",
        ] + common
    return [
        "Do not call back this number and do not follow any instructions given in the call.",
        "If you already shared financial details, contact your bank immediately to block your accounts.",
        "File a complaint at cybercrime.gov.in or call the national cybercrime helpline 1930.",
        "Block the number and report it as fraud in your phone app.",
    ] + common
