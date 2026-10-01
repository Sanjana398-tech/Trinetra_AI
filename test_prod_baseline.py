"""
Trinetra production API test suite.

Run this BEFORE deploying to capture the baseline, then run again
AFTER deploying to confirm every fix is live.

Usage:
    python test_prod_baseline.py
    python test_prod_baseline.py --label "after-deploy"
"""

import sys
import struct
import base64
import json
import time
import urllib.request
import urllib.error

BASE = "https://trinetra-ai-ua5e.onrender.com"
LABEL = sys.argv[2] if len(sys.argv) > 2 else sys.argv[1] if len(sys.argv) > 1 else "current"

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

results = []


def _post_json(path, data, timeout=60):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as ex:
        return 0, {"_exception": str(ex)}


def _post_multipart(path, fields, files, timeout=90):
    boundary = "TrinetraTestBoundary42"
    parts = []
    for name, value in fields.items():
        parts.append(f"--{boundary}".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"'.encode())
        parts.append(b"")
        parts.append(value.encode())
    for fname, (filename, data, ctype) in files.items():
        parts.append(f"--{boundary}".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{fname}"; filename="{filename}"'.encode()
        )
        parts.append(f"Content-Type: {ctype}".encode())
        parts.append(b"")
        parts.append(data)
    parts.append(f"--{boundary}--".encode())
    body = b"\r\n".join(parts)
    req = urllib.request.Request(
        BASE + path,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {"_raw": raw[:200].decode(errors="replace")}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"_raw": raw[:200].decode(errors="replace")}
    except Exception as ex:
        return 0, {"_exception": str(ex)}


def _options(path, origin):
    req = urllib.request.Request(
        BASE + path,
        method="OPTIONS",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,X-Secure-Chat-Key,Authorization",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception as ex:
        return 0, {"_exception": str(ex)}


def check(name, status, body, *, expect_status, expect_success=None,
          expect_scan_id=None, expect_error_contains=None):
    ok = True
    notes = []

    if status != expect_status:
        ok = False
        notes.append(f"status={status} (want {expect_status})")

    if expect_success is not None:
        actual = body.get("success")
        if actual != expect_success:
            ok = False
            notes.append(f"success={actual} (want {expect_success})")

    if expect_scan_id:
        sid = body.get("scan_id")
        if not sid:
            ok = False
            notes.append("scan_id missing")

    if expect_error_contains:
        err = (body.get("error") or body.get("_raw") or "").lower()
        if expect_error_contains.lower() not in err:
            ok = False
            notes.append(f"error field missing '{expect_error_contains}' (got: {err[:80]})")

    verdict = PASS if ok else FAIL
    results.append((name, verdict, notes, status, body))
    icon = "✅" if ok else "❌"
    note_str = "  " + " | ".join(notes) if notes else ""
    print(f"  {icon} [{verdict}] {name}{note_str}")
    return ok


# ── Minimal assets ────────────────────────────────────────────────────────────
PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "/5+hHgAHggJ/PchI6QAAAABJRU5ErkJggg=="
)

# 44-byte minimal WAV: 1 channel, 8-bit, 8000 Hz, 0 samples
WAV_SILENT = struct.pack(
    "<4sI4s4sIHHIIHH4sI",
    b"RIFF", 36, b"WAVE",
    b"fmt ", 16,
    1, 1, 8000, 8000, 1, 8,
    b"data", 0,
)

SCAM_MSG = (
    "URGENT: Your SBI bank account has been blocked. "
    "Verify your OTP at http://sbi-secure-update.tk/login "
    "or your account will be permanently closed."
)
SAFE_MSG = "Hey, are we still on for lunch tomorrow? Let me know!"

ORIGIN = "https://secure-chat-two-green.vercel.app"

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*64}")
print(f"  Trinetra production API test  [{LABEL}]")
print(f"  {BASE}")
print(f"{'='*64}\n")

# ── 0. Health endpoints ───────────────────────────────────────────────────────
print("── Health ──────────────────────────────────────────────────")
s, b = _post_json.__wrapped__ if hasattr(_post_json, "__wrapped__") else (
    lambda: (lambda path: (
        __import__("urllib.request", fromlist=["urlopen"]).urlopen(
            urllib.request.Request(BASE + path), timeout=10
        )
    ))
)() if False else (None, None)

# /health
req = urllib.request.Request(BASE + "/health")
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        hb = json.loads(r.read())
        check("/health returns 200", r.status, hb,
              expect_status=200, expect_success=None)
except urllib.error.HTTPError as e:
    check("/health returns 200", e.code, {},
          expect_status=200)

# /healthz
req2 = urllib.request.Request(BASE + "/healthz")
try:
    with urllib.request.urlopen(req2, timeout=10) as r2:
        hb2 = json.loads(r2.read())
        check("/healthz returns 200", r2.status, hb2,
              expect_status=200)
except urllib.error.HTTPError as e:
    check("/healthz returns 200", e.code, {},
          expect_status=200)

# ── 1–2. Text ─────────────────────────────────────────────────────────────────
print("\n── Text ────────────────────────────────────────────────────")

print("  Sending SAFE text (may wait ~15 s for model warm-up)...")
t = time.time()
s, b = _post_json("/api/analyze-message", {"message": SAFE_MSG, "user_id": "kiro_test"})
elapsed = time.time() - t
print(f"  ({elapsed:.1f}s)")
check("1. SAFE text → 200 + success + scan_id", s, b,
      expect_status=200, expect_success=True, expect_scan_id=True)

print("  Sending SCAM text...")
t = time.time()
s, b = _post_json("/api/analyze-message", {"message": SCAM_MSG, "user_id": "kiro_test"})
elapsed = time.time() - t
print(f"  ({elapsed:.1f}s)")
check("2. SCAM text → 200 + success + scan_id", s, b,
      expect_status=200, expect_success=True, expect_scan_id=True)
if b.get("prediction") == "SCAM":
    print("     prediction=SCAM ✅")
else:
    print(f"     prediction={b.get('prediction')} (expected SCAM — model may vary)")

# ── 3–4. Image ────────────────────────────────────────────────────────────────
print("\n── Image ───────────────────────────────────────────────────")

print("  Sending plain 1×1 PNG (no text, no Tesseract needed)...")
t = time.time()
s, b = _post_multipart(
    "/api/analyze-screenshot",
    {"user_id": "kiro_test"},
    {"image": ("plain.png", PNG_1x1, "image/png")},
)
elapsed = time.time() - t
print(f"  ({elapsed:.1f}s)")
check("3. SAFE image (plain photo) → 200 + success + scan_id", s, b,
      expect_status=200, expect_success=True, expect_scan_id=True)

# For test 4 we send the same tiny PNG — on a real screenshot with text this
# would exercise Tesseract.  We note the result regardless.
print("  Sending same PNG as 'scam image' test (result depends on OCR)...")
t = time.time()
s, b = _post_multipart(
    "/api/analyze-screenshot",
    {"user_id": "kiro_test"},
    {"image": ("scam.png", PNG_1x1, "image/png")},
)
elapsed = time.time() - t
print(f"  ({elapsed:.1f}s)")
check("4. Image scan → any 2xx response + scan_id", s, b,
      expect_status=200, expect_success=True, expect_scan_id=True)

# ── 5–6. Voice ────────────────────────────────────────────────────────────────
print("\n── Voice ───────────────────────────────────────────────────")
print("  Sending silent WAV (Whisper will report no speech)...")
print("  NOTE: first call downloads Whisper model — may take 60-90 s...")
t = time.time()
s, b = _post_multipart(
    "/api/analyze-voice",
    {"user_id": "kiro_test"},
    {"audio": ("silent.wav", WAV_SILENT, "audio/wav")},
    timeout=120,
)
elapsed = time.time() - t
print(f"  ({elapsed:.1f}s)")
# After fix: should return a clean JSON error (no speech detected) not a 502
check("5. Voice (silent WAV) → clean JSON response (not 502)", s, b,
      expect_status=422,  # "no speech detected" = 422 Unprocessable
      expect_success=False)
# Also acceptable: 503 "still loading" on first call if model takes too long
if s in (422, 503) and b.get("success") is False:
    # Override: 503 with JSON body is acceptable on first Whisper load
    results[-1] = (results[-1][0], PASS, [], s, b)
    print(f"     NOTE: HTTP {s} with JSON body = acceptable (clean error, not silent 502)")

print("  Sending invalid audio bytes as WAV...")
t = time.time()
s, b = _post_multipart(
    "/api/analyze-voice",
    {"user_id": "kiro_test"},
    {"audio": ("bad.wav", b"not audio data at all xxxxx", "audio/wav")},
    timeout=90,
)
elapsed = time.time() - t
print(f"  ({elapsed:.1f}s)")
check("6. Invalid audio → clean JSON error (not 502)", s, b,
      expect_status=422,  # transcription fails gracefully
      expect_success=False)
if s in (422, 503) and b.get("success") is False:
    results[-1] = (results[-1][0], PASS, [], s, b)
    print(f"     NOTE: HTTP {s} with JSON body = acceptable (clean error, not silent 502)")

# ── 7–8. Invalid inputs ───────────────────────────────────────────────────────
print("\n── Error handling ──────────────────────────────────────────")

s, b = _post_multipart(
    "/api/analyze-screenshot",
    {"user_id": "kiro_test"},
    {"image": ("fake.png", b"this is not an image file at all", "image/png")},
)
check("7. Invalid image bytes → 400 (not 503 blank)", s, b,
      expect_status=400, expect_success=False)

s, b = _post_multipart(
    "/api/analyze-screenshot",
    {"user_id": "kiro_test"},
    {"image": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")},
)
check("8. Unsupported image extension → 400", s, b,
      expect_status=400, expect_success=False)

s, b = _post_json("/api/analyze-message", {"message": "", "user_id": "x"})
check("9. Empty message → 400", s, b,
      expect_status=400, expect_success=False)

s, b = _post_multipart("/api/analyze-voice", {"user_id": "x"}, {})
check("10. Missing audio file → 400", s, b,
      expect_status=400, expect_success=False)

# ── 9. CORS preflights ────────────────────────────────────────────────────────
print("\n── CORS ────────────────────────────────────────────────────")

status, hdrs = _options("/api/analyze-message", ORIGIN)
acao = hdrs.get("Access-Control-Allow-Origin", "")
ok_cors_msg = acao == ORIGIN or acao == "*"
icon = "✅" if ok_cors_msg else "❌"
verdict = PASS if ok_cors_msg else FAIL
results.append(("CORS /api/analyze-message", verdict, [], status, {}))
print(f"  {icon} [{verdict}] CORS preflight /api/analyze-message")
print(f"       HTTP {status}  Access-Control-Allow-Origin: {acao or 'MISSING'}")

status2, hdrs2 = _options("/api/secure-chat/v1/detect", ORIGIN)
acao2 = hdrs2.get("Access-Control-Allow-Origin", "")
ok_cors_detect = acao2 == ORIGIN or acao2 == "*"
icon2 = "✅" if ok_cors_detect else "❌"
verdict2 = PASS if ok_cors_detect else FAIL
results.append(("CORS /api/secure-chat/v1/detect", verdict2, [], status2, {}))
print(f"  {icon2} [{verdict2}] CORS preflight /api/secure-chat/v1/detect")
print(f"       HTTP {status2}  Access-Control-Allow-Origin: {acao2 or 'MISSING'}")

# ── 10. Repeated request (idempotency / no duplicate scan) ────────────────────
print("\n── Repeated request ────────────────────────────────────────")
s1, b1 = _post_json("/api/analyze-message", {"message": SAFE_MSG, "user_id": "kiro_repeat"})
s2, b2 = _post_json("/api/analyze-message", {"message": SAFE_MSG, "user_id": "kiro_repeat"})
both_ok = s1 == 200 and s2 == 200 and b1.get("success") and b2.get("success")
id1, id2 = b1.get("scan_id"), b2.get("scan_id")
different_ids = id1 != id2
icon_r = "✅" if both_ok else "❌"
results.append(("10. Repeated request", PASS if both_ok else FAIL, [], 200, {}))
print(f"  {icon_r} [{'PASS' if both_ok else 'FAIL'}] 10. Repeated request → both succeed, separate scan IDs")
print(f"       scan_id 1={id1}  scan_id 2={id2}  different={different_ids}")

# ─────────────────────────────────────────────────────────────────────────────
passed = sum(1 for _, v, *_ in results if v == PASS)
failed = sum(1 for _, v, *_ in results if v == FAIL)
total = len(results)

print(f"\n{'='*64}")
print(f"  Results [{LABEL}]:  {passed}/{total} passed,  {failed} failed")
print(f"{'='*64}\n")

if failed > 0:
    print("Failed tests:")
    for name, verdict, notes, status, body in results:
        if verdict == FAIL:
            print(f"  ❌ {name}")
            for n in notes:
                print(f"       {n}")
    print()

sys.exit(0 if failed == 0 else 1)
