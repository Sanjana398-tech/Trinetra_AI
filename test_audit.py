# -*- coding: utf-8 -*-
"""
TRINETRA AI x SECURE CHAT - Complete End-to-End Audit
Run:  python test_audit.py
"""
import json
import sys

PASS = []
FAIL = []

def ok(label):
    PASS.append(label)
    print("  PASS  " + label)

def fail(label, reason=""):
    FAIL.append(label)
    msg = "  FAIL  " + label
    if reason:
        msg += "  [" + str(reason)[:120] + "]"
    print(msg)

def check(label, condition, reason=""):
    if condition:
        ok(label)
    else:
        fail(label, reason)

from app import create_app
app = create_app()

# ===========================================================
# SECTION 1 - Route registration
# ===========================================================
print("\n-- SECTION 1: Route registration --")
with app.app_context():
    rules = {r.rule for r in app.url_map.iter_rules()}
    for route in ["/api/analyze-message", "/api/analyze-url",
                  "/api/analyze-upi", "/api/analyze-voice",
                  "/api/analyze-screenshot"]:
        check("Route " + route + " registered", route in rules)

# ===========================================================
# SECTION 2 - Model availability
# ===========================================================
print("\n-- SECTION 2: Model availability --")
with app.app_context():
    from backend.utils.distilbert_loader import model as db_model, tokenizer as db_tok
    check("DistilBERT model loaded",     db_model is not None)
    check("DistilBERT tokenizer loaded", db_tok is not None)
    from backend.utils.xgboost_loader import model as url_m, feature_columns as url_fc
    check("XGBoost URL model loaded",    url_m is not None)
    check("XGBoost feature_columns",     url_fc is not None)

# ===========================================================
# SECTION 3 - XAI helper unit tests (no network calls)
# ===========================================================
print("\n-- SECTION 3: XAI helper unit tests --")
with app.app_context():
    from backend.routes.api import _build_xai

    # 3a SAFE
    xai = _build_xai("Hi your order is on its way.", "safe", 99.9, "en")
    check("3a SAFE xai_available=False",  xai["xai_available"] is False)
    check("3a SAFE reasons=[]",           xai["reasons"] == [])
    check("3a SAFE tips=[]",              xai["tips"] == [])
    check("3a SAFE speech_text=''",       xai["speech_text"] == "")
    check("3a SAFE speech_language=en",   xai["speech_language"] == "en")

    # 3b SCAM urgency+OTP+link
    msg = "URGENT: Account expires in 2 hours. Send OTP to http://bit.ly/verify to avoid block."
    xai = _build_xai(msg, "scam", 99.8, "en")
    check("3b SCAM xai_available=True",    xai["xai_available"] is True)
    check("3b SCAM reasons >= 2",          len(xai["reasons"]) >= 2)
    check("3b SCAM tips >= 2",             len(xai["tips"]) >= 2)
    check("3b SCAM speech_text non-empty", len(xai["speech_text"]) > 10)
    check("3b SCAM speech mentions scam or warning",
          any(w in xai["speech_text"].lower() for w in ["scam","warning","detected","suspicious"]))

    # 3c Urgency pattern fires
    xai_u = _build_xai("Act now immediately or account blocked permanently.", "scam", 98.0, "en")
    check("3c urgency pattern fires",
          any("urgency" in r.lower() or "pressure" in r.lower() for r in xai_u["reasons"]),
          str(xai_u["reasons"]))

    # 3d OTP/financial pattern fires
    xai_o = _build_xai("Share your OTP and CVV immediately to verify your bank account.", "scam", 97.0, "en")
    check("3d OTP/financial fires",
          any("otp" in r.lower() or "financial" in r.lower() or "pin" in r.lower() for r in xai_o["reasons"]),
          str(xai_o["reasons"]))

    # 3e KYC pattern fires
    xai_k = _build_xai("Update your KYC now or your account will be suspended.", "scam", 95.0, "en")
    check("3e KYC pattern fires",
          any("kyc" in r.lower() or "verify" in r.lower() or "impersonat" in r.lower() for r in xai_k["reasons"]),
          str(xai_k["reasons"]))

    # 3f Prize/lottery pattern fires
    xai_p = _build_xai("Congratulations you won a lottery prize of Rs 1 lakh.", "scam", 96.0, "en")
    check("3f prize/lottery fires",
          any("prize" in r.lower() or "lottery" in r.lower() or "won" in r.lower() for r in xai_p["reasons"]),
          str(xai_p["reasons"]))

    # 3g Suspicious link fires
    xai_l = _build_xai("Click here: https://secure-verify.tk/login to update your details.", "scam", 94.0, "en")
    check("3g suspicious link fires",
          any("link" in r.lower() or "domain" in r.lower() or "url" in r.lower() for r in xai_l["reasons"]),
          str(xai_l["reasons"]))

    # 3h No reasons invented for safe
    xai_s = _build_xai("The meeting is at 3pm tomorrow please join on time.", "safe", 99.0, "en")
    check("3h safe: no reasons invented", xai_s["reasons"] == [])

    # 3i Urgency-only: no prize/OTP invented
    xai_uo = _build_xai("Act now! Last chance. Offer expires immediately.", "scam", 89.0, "en")
    check("3i urgency-only: no prize invented",
          not any("prize" in r.lower() or "lottery" in r.lower() for r in xai_uo["reasons"]),
          str(xai_uo["reasons"]))
    check("3i urgency-only: no OTP invented",
          not any("otp" in r.lower() for r in xai_uo["reasons"]),
          str(xai_uo["reasons"]))

    # 3j Link-only: no KYC invented
    xai_lo = _build_xai("Check this out: http://bit.ly/abc123", "scam", 85.0, "en")
    check("3j link-only: no KYC invented",
          not any("kyc" in r.lower() for r in xai_lo["reasons"]),
          str(xai_lo["reasons"]))

    # 3k Generic scam: fallback reason present
    xai_g = _build_xai("xyz abc pqr unusual wording def.", "scam", 72.0, "en")
    check("3k generic scam: at least 1 reason", len(xai_g["reasons"]) >= 1)

# ===========================================================
# SECTION 4 - analyze-message: required fields
# ===========================================================
print("\n-- SECTION 4: analyze-message required fields --")

REQUIRED = {
    "success", "prediction", "prediction_label",
    "confidence", "confidence_label",
    "safe_probability", "safe_label",
    "scam_probability", "scam_label",
    "probability_label", "alert", "language", "scan_id",
    "xai_available", "reasons", "tips", "speech_text", "speech_language",
    "verdict_label", "risk_label", "view_record_label",
}

with app.test_client() as c:
    # 4a SAFE
    r = c.post("/api/analyze-message",
               data=json.dumps({"message": "Hi your parcel is out for delivery today.", "user_id": "audit"}),
               content_type="application/json")
    d = r.get_json()
    check("4a SAFE status=200",           r.status_code == 200)
    check("4a SAFE success=True",         d.get("success") is True)
    check("4a SAFE prediction=SAFE",      d.get("prediction") == "SAFE")
    for f in sorted(REQUIRED):
        check("4a SAFE field:" + f,       f in d, "missing")
    check("4a SAFE xai_available=False",  d.get("xai_available") is False)
    check("4a SAFE reasons=[]",           d.get("reasons") == [])
    check("4a SAFE speech_text=''",       d.get("speech_text") == "")
    check("4a SAFE scan_id is int",       isinstance(d.get("scan_id"), int))

    # 4b SCAM
    r = c.post("/api/analyze-message",
               data=json.dumps({
                   "message": "Congratulations you won Rs 100000 lottery. "
                              "Send OTP and bank account now. Offer expires immediately.",
                   "user_id": "audit"}),
               content_type="application/json")
    d = r.get_json()
    check("4b SCAM status=200",           r.status_code == 200)
    check("4b SCAM success=True",         d.get("success") is True)
    check("4b SCAM prediction=SCAM",      d.get("prediction") == "SCAM")
    for f in sorted(REQUIRED):
        check("4b SCAM field:" + f,       f in d, "missing")
    check("4b SCAM xai_available=True",   d.get("xai_available") is True)
    check("4b SCAM reasons non-empty",    len(d.get("reasons", [])) >= 1)
    check("4b SCAM tips non-empty",       len(d.get("tips", [])) >= 1)
    check("4b SCAM speech non-empty",     len(d.get("speech_text", "")) > 5)
    check("4b SCAM speech_language=en",   d.get("speech_language") == "en")
    check("4b SCAM scan_id is int",       isinstance(d.get("scan_id"), int))

    # 4c KYC/OTP
    r = c.post("/api/analyze-message",
               data=json.dumps({
                   "message": "Dear customer your KYC is pending. "
                              "Share OTP and UPI PIN to verify account immediately.",
                   "user_id": "audit"}),
               content_type="application/json")
    d = r.get_json()
    check("4c KYC/OTP success=True",  d.get("success") is True)
    if d.get("prediction") == "SCAM":
        check("4c KYC/OTP xai=True", d.get("xai_available") is True)
        check("4c KYC/OTP OTP/KYC reason",
              any("otp" in r2.lower() or "kyc" in r2.lower() or "financial" in r2.lower()
                  for r2 in d.get("reasons", [])),
              str(d.get("reasons", [])))
    else:
        ok("4c KYC/OTP model=SAFE (xai=False is correct)")

    # 4d URL message
    r = c.post("/api/analyze-message",
               data=json.dumps({
                   "message": "Click here to verify your account: http://bit.ly/secure-login-now",
                   "user_id": "audit"}),
               content_type="application/json")
    d = r.get_json()
    check("4d URL msg success=True",  d.get("success") is True)
    if d.get("prediction") == "SCAM":
        check("4d URL msg link reason",
              any("link" in r2.lower() or "url" in r2.lower() or "domain" in r2.lower()
                  for r2 in d.get("reasons", [])),
              str(d.get("reasons", [])))
    else:
        ok("4d URL msg model=SAFE (xai=False is correct)")

    # 4e Empty message -> 400
    r = c.post("/api/analyze-message",
               data=json.dumps({"message": ""}),
               content_type="application/json")
    check("4e empty message: 400", r.status_code == 400)

    # 4f Wrong content-type -> 400
    r = c.post("/api/analyze-message", data="hello", content_type="text/plain")
    check("4f bad content-type: 400", r.status_code == 400)

    # 4g language field echoed back
    r = c.post("/api/analyze-message",
               data=json.dumps({"message": "Share OTP now.", "language": "en"}),
               content_type="application/json")
    d = r.get_json()
    check("4g language echoed in response", d.get("language") == "en")

# ===========================================================
# SECTION 5 - analyze-url
# ===========================================================
print("\n-- SECTION 5: analyze-url --")
with app.test_client() as c:
    r = c.post("/api/analyze-url",
               data=json.dumps({"url": "http://secure-icicibank-verify.tk/login", "user_id": "audit"}),
               content_type="application/json")
    d = r.get_json()
    check("5a URL status=200",       r.status_code == 200)
    check("5a URL success=True",     d.get("success") is True)
    check("5a URL prediction set",   "prediction" in d)
    check("5a URL confidence set",   "confidence" in d)
    check("5a URL scan_id is int",   isinstance(d.get("scan_id"), int))
    check("5a URL reasons present",  "reasons" in d)
    check("5a URL language set",     "language" in d)

    r = c.post("/api/analyze-url",
               data=json.dumps({"url": ""}),
               content_type="application/json")
    check("5b URL empty: 400",  r.status_code == 400)

# ===========================================================
# SECTION 6 - Static multilingual catalog
# ===========================================================
print("\n-- SECTION 6: Multilingual static catalog --")
with app.app_context():
    from backend.utils.localization import translate, normalize_language

    for lang in ["hi", "kn", "te", "ta", "ml"]:
        for key in ["safe", "suspicious", "scam", "Confidence", "Risk Score"]:
            val = translate(key, lang)
            check("6 " + lang + " '" + key + "' translated",
                  val != key and len(val) > 1,
                  "got: " + repr(val))

    check("6 en safe=SAFE",          translate("safe", "en") == "SAFE")
    check("6 en scam=SCAM",          translate("scam", "en") == "SCAM")
    check("6 en suspicious=SUSPICIOUS", translate("suspicious", "en") == "SUSPICIOUS")
    check("6 normalize unknown->en", normalize_language("xyz") == "en")
    check("6 normalize None->en",    normalize_language(None) == "en")

# ===========================================================
# SECTION 7 - ScanHistory persistence
# ===========================================================
print("\n-- SECTION 7: ScanHistory persistence --")
with app.test_client() as c:
    r = c.post("/api/analyze-message",
               data=json.dumps({
                   "message": "URGENT Share your OTP and bank PIN or account blocked.",
                   "user_id": "audit-persist"}),
               content_type="application/json")
    d = r.get_json()
    scan_id = d.get("scan_id")
    check("7 scan_id returned",     isinstance(scan_id, int))

    if isinstance(scan_id, int):
        with app.app_context():
            from backend.db_models import ScanHistory
            record = ScanHistory.query.get(scan_id)
            check("7 record in DB",          record is not None)
            if record:
                check("7 scan_type=message",  record.scan_type == "message")
                check("7 source=secure-chat", record.source == "secure-chat")
                check("7 ext_user_id set",    record.external_user_id == "audit-persist")
                check("7 verdict lowercase",  record.verdict == record.verdict.lower())
                check("7 confidence > 0",     record.confidence_score > 0)
                check("7 risk_score >= 0",    record.risk_score >= 0)
                check("7 explanation set",    bool(record.explanation))

# ===========================================================
# SECTION 8 - No invented reasons
# ===========================================================
print("\n-- SECTION 8: Reasons are message-specific, never invented --")
with app.app_context():
    from backend.routes.api import _build_xai

    # Urgency only — no prize/OTP
    xai = _build_xai("Act now last chance offer expires immediately.", "scam", 89.0, "en")
    check("8a no prize for urgency-only",
          not any("prize" in r.lower() or "lottery" in r.lower() for r in xai["reasons"]),
          str(xai["reasons"]))
    check("8a no OTP for urgency-only",
          not any("otp" in r.lower() for r in xai["reasons"]),
          str(xai["reasons"]))

    # Link only — no KYC
    xai = _build_xai("Check: http://bit.ly/abc123", "scam", 85.0, "en")
    check("8b no KYC for link-only",
          not any("kyc" in r.lower() for r in xai["reasons"]),
          str(xai["reasons"]))

    # Safe — always empty
    xai = _build_xai("Can we meet for the project review tomorrow at 3pm?", "safe", 99.9, "en")
    check("8c safe: reasons=[]",   xai["reasons"] == [])
    check("8c safe: tips=[]",      xai["tips"] == [])
    check("8c safe: speech=''",    xai["speech_text"] == "")

# ===========================================================
# SECTION 9 - speech_text quality
# ===========================================================
print("\n-- SECTION 9: speech_text quality --")
with app.app_context():
    from backend.routes.api import _build_xai

    xai = _build_xai(
        "Congratulations you won Rs 50000 lottery prize. "
        "Share OTP and bank account to claim. Expires in 2 hours. "
        "Click http://bit.ly/claim-now",
        "scam", 99.9, "en")
    st = xai["speech_text"]
    check("9 speech contains warning/scam",
          any(w in st.lower() for w in ["warning","scam","detected","suspicious"]))
    check("9 speech contains safety advice",
          any(w in st.lower() for w in ["link","detail","share","personal"]))
    check("9 speech max 600 chars",   len(st) <= 600,  "len=" + str(len(st)))
    check("9 speech min 30 chars",    len(st) >= 30,   "len=" + str(len(st)))
    check("9 speech_language=en",     xai["speech_language"] == "en")
    # Must not be raw reasons concatenated verbatim
    check("9 speech is synthesized sentence",
          st != " ".join(xai["reasons"]))

# ===========================================================
# SECTION 10 - language round-trip (static translations, no network)
# ===========================================================
print("\n-- SECTION 10: language round-trip --")
# Use English message only — we test language= param routing and static catalog
# Non-English messages would call Google Translate (rate-limited in test env)
with app.test_client() as c:
    for lang in ["en", "hi", "kn", "te", "ta", "ml"]:
        r = c.post("/api/analyze-message",
                   data=json.dumps({
                       "message": "Share OTP immediately or your account will be blocked.",
                       "user_id": "lang-test",
                       "language": lang}),
                   content_type="application/json")
        d = r.get_json()
        check("10 " + lang + " status=200",          r.status_code == 200)
        check("10 " + lang + " language in response", d.get("language") == lang)
        check("10 " + lang + " speech_language",      d.get("speech_language") == lang)
        check("10 " + lang + " prediction present",   "prediction" in d)
        check("10 " + lang + " scan_id present",      "scan_id" in d)
        check("10 " + lang + " xai_available set",    "xai_available" in d)

# ===========================================================
# FINAL REPORT
# ===========================================================
total = len(PASS) + len(FAIL)
print("\n" + "="*60)
print("AUDIT COMPLETE: " + str(len(PASS)) + "/" + str(total) + " PASSED,  " + str(len(FAIL)) + " FAILED")
print("="*60)
if FAIL:
    print("\nFailed checks:")
    for f2 in FAIL:
        print("  FAIL  " + f2)
    sys.exit(1)
else:
    print("All checks passed.")
    sys.exit(0)
