"""Focused end-to-end coverage for the public analysis API routes."""

import unittest
from io import BytesIO
from unittest.mock import patch

import cv2

from backend import create_app
from backend.db_models import ScanHistory
from backend.extensions import db


def _classification(verdict, engine="test-engine"):
    risk = {"safe": 4.0, "suspicious": 58.0, "scam": 92.0}[verdict]
    return {
        "engine": engine,
        "verdict": verdict,
        "confidence": 94.0,
        "risk": risk,
        "reasons": ["Matched test indicator"],
        "tips": ["Verify independently"],
    }


def _qr_png(payload):
    matrix = cv2.QRCodeEncoder_create().encode(payload)
    matrix = cv2.copyMakeBorder(matrix, 24, 24, 24, 24, cv2.BORDER_CONSTANT, value=255)
    image = cv2.resize(matrix, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST)
    success, encoded = cv2.imencode(".png", image)
    if not success:
        raise RuntimeError("Could not encode QR fixture")
    return encoded.tobytes()


class AnalysisApiEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def _assert_detection(self, response, scan_type, verdict, language="en"):
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["classification"], verdict.upper())
        self.assertTrue(body["scan_id"])
        self.assertEqual(body["language"], language)
        self.assertEqual(
            body["type"],
            {"message": "text", "screenshot": "image"}.get(scan_type, scan_type),
        )
        self.assertGreaterEqual(body["risk_score"], 0)
        self.assertLessEqual(body["risk_score"], 100)
        self.assertEqual(body["alert_required"], verdict != "safe")
        self.assertEqual(ScanHistory.query.filter_by(scan_type=scan_type).count(), 1)
        return body

    def _clear_scans(self):
        db.session.query(ScanHistory).delete()
        db.session.commit()

    def test_text_safe_and_scam(self):
        safe_prediction = {
            "prediction": "SAFE",
            "confidence": 97.0,
            "safe_probability": 97.0,
            "scam_probability": 3.0,
        }
        scam_prediction = {
            "prediction": "SCAM",
            "confidence": 96.0,
            "safe_probability": 4.0,
            "scam_probability": 96.0,
        }
        with patch("backend.utils.distilbert_loader.model", object()), patch(
            "backend.utils.distilbert_loader.tokenizer", object()
        ), patch(
            "backend.utils.distilbert_loader.predict_message",
            side_effect=[safe_prediction, scam_prediction],
        ):
            for verdict, text in (
                ("safe", "Lunch at noon tomorrow?"),
                ("scam", "Your bank account is blocked; send your OTP now."),
            ):
                with self.subTest(verdict=verdict):
                    response = self.client.post(
                        "/api/analyze-message",
                        json={"message": text, "user_id": "local-e2e"},
                    )
                    self._assert_detection(response, "message", verdict)
                    self._clear_scans()

    def test_text_language_is_detected_from_content(self):
        with patch(
            "backend.routes.api.detect_text",
            return_value=(_classification("scam", "DistilBERT"), {}, None),
        ), patch("backend.routes.api.to_english", return_value="English text"), patch(
            "backend.routes.api.translate", side_effect=lambda text, _language: text
        ):
            response = self.client.post(
                "/api/analyze-message",
                json={"message": "आपका खाता बंद हो जाएगा"},
            )

        self._assert_detection(response, "message", "scam", language="hi")

    def test_url_safe_and_phishing(self):
        with patch(
            "backend.utils.detection.classify_url",
            side_effect=[_classification("safe", "url"), _classification("scam", "url")],
        ):
            for verdict, url in (
                ("safe", "https://www.google.com"),
                ("scam", "http://sbi-secure-update.tk/login"),
            ):
                with self.subTest(verdict=verdict):
                    response = self.client.post("/api/analyze-url", json={"url": url})
                    self._assert_detection(response, "url", verdict)
                    self._clear_scans()

    def test_upi_safe_and_risky(self):
        with patch(
            "backend.utils.detection.classify_upi",
            side_effect=[_classification("safe", "upi"), _classification("scam", "upi")],
        ):
            for verdict, upi_id in (("safe", "alice@okaxis"), ("scam", "fraud@badbank")):
                with self.subTest(verdict=verdict):
                    response = self.client.post(
                        "/api/analyze-upi",
                        json={"upi_id": upi_id, "amount": 500, "note": "invoice"},
                    )
                    self._assert_detection(response, "upi", verdict)
                    self._clear_scans()

    def test_qr_url_upi_and_text_payloads(self):
        cases = (
            ("https://sbi-secure-update.tk/login", "url", "scam", "qr-url"),
            ("upi://pay?pa=fraud%40badbank&pn=Refund&am=5000", "upi", "scam", "qr-upi"),
            ("Urgent: claim your prize now", "message", "suspicious", "qr-text"),
        )
        with patch(
            "backend.utils.detection.classify_url", return_value=_classification("scam", "url")
        ), patch(
            "backend.utils.detection.classify_upi", return_value=_classification("scam", "upi")
        ), patch(
            "backend.utils.detection.classify_message",
            return_value=_classification("suspicious", "DistilBERT"),
        ):
            for payload, scan_type, verdict, analysis_type in cases:
                with self.subTest(analysis_type=analysis_type):
                    response = self.client.post(
                        "/api/analyze-qr",
                        data={"image": (BytesIO(_qr_png(payload)), "payload.png")},
                    )
                    body = self._assert_detection(response, "qr", verdict)
                    self.assertEqual(body["type"], "qr")
                    self.assertEqual(body["analysis_type"], analysis_type)
                    self.assertEqual(body["decoded_content"], payload)
                    self._clear_scans()

    def test_plain_and_payment_screenshot_images(self):
        with patch("backend.utils.detection.decode_qr", return_value=(None, "no QR")), patch(
            "backend.utils.detection.extract_text",
            side_effect=["", "Payment received Rs 500 from alice@okaxis. UTR 123456789012."],
        ), patch(
            "backend.utils.detection.parse_fields",
            return_value={"amount": "500", "upi_id": "alice@okaxis", "transaction_id": "123456789012"},
        ), patch(
            "backend.utils.detection._ocr_analyze",
            return_value={
                "verdict": "suspicious",
                "confidence": 82.0,
                "risk": 55.0,
                "reasons": ["Payment details require verification."],
            },
        ), patch(
            "backend.utils.detection._ocr_safety_tips", return_value=["Verify the transaction"]
        ):
            cases = (("safe", "plain photo"), ("suspicious", "payment screenshot"))
            for verdict, filename in cases:
                with self.subTest(image=filename):
                    response = self.client.post(
                        "/api/analyze-screenshot",
                        data={"image": (BytesIO(b"valid-enough-for-mocked-ocr"), "scan.png")},
                    )
                    body = self._assert_detection(response, "screenshot", verdict)
                    self.assertEqual(body["type"], "image")
                    self.assertEqual(
                        body["analysis_type"],
                        "photo" if verdict == "safe" else "payment-screenshot",
                    )
                    self._clear_scans()

    def test_voice_wav_upload(self):
        prediction = {
            "prediction": "SCAM",
            "confidence": 95.0,
            "safe_probability": 5.0,
            "scam_probability": 95.0,
        }
        with patch(
            "backend.utils.voice_transcribe.transcribe_audio",
            return_value=("Transfer money now to prevent account closure", None),
        ), patch("backend.utils.distilbert_loader.model", object()), patch(
            "backend.utils.distilbert_loader.tokenizer", object()
        ), patch("backend.utils.distilbert_loader.predict_message", return_value=prediction):
            response = self.client.post(
                "/api/analyze-voice",
                data={"audio": (BytesIO(b"mocked wav upload"), "voice.wav")},
            )

        body = self._assert_detection(response, "voice", "scam")
        self.assertEqual(body["transcription"], "Transfer money now to prevent account closure")

    def test_error_cases(self):
        cases = (
            (
                self.client.post("/api/analyze-message", json={"message": ""}),
                400,
                "success",
            ),
            (
                self.client.post(
                    "/api/analyze-upi", json={"upi_id": "", "amount": "not-a-number"}
                ),
                400,
                "success",
            ),
            (
                self.client.post(
                    "/api/analyze-qr",
                    data={"image": (BytesIO(b"bad"), "payload.exe")},
                ),
                400,
                "success",
            ),
            (self.client.post("/api/analyze-voice", data={}), 400, "success"),
            (
                self.client.post(
                    "/api/analyze-screenshot",
                    data={"image": (BytesIO(b"bad image bytes"), "bad.png")},
                ),
                422,
                "success",
            ),
        )
        for response, expected_status, key in cases:
            with self.subTest(status=expected_status, error=response.get_json()):
                self.assertEqual(response.status_code, expected_status, response.get_json())
                self.assertFalse(response.get_json()[key])

    def test_scan_history_write_failure_returns_server_error(self):
        with patch(
            "backend.utils.detection.db.session.commit",
            side_effect=RuntimeError("database unavailable"),
        ):
            response = self.client.post(
                "/api/analyze-url",
                json={"url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 500, response.get_json())
        self.assertFalse(response.get_json()["success"])
        self.assertIn("error", response.get_json())


if __name__ == "__main__":
    unittest.main()