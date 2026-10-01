import unittest
from io import BytesIO
from urllib.parse import parse_qs, urlsplit
import time
from unittest.mock import patch

from backend import create_app
from backend.db_models import ScanHistory, SecureChatAuthorizationCode, User
from backend.extensions import db


class SecureChatIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app.config.update(
            SECURE_CHAT_API_KEY="test-server-secret",
            SECURE_CHAT_REDIRECT_URI="https://chat.example.com/integrations/trinetra/callback",
        )
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        self.user = User(
            full_name="Integration Tester",
            email="integration@example.com",
            password_hash="test",
        )
        db.session.add(self.user)
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def _service_headers(self):
        return {"X-Secure-Chat-Key": "test-server-secret"}

    def _enable_and_exchange(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.user.id)
            session["_fresh"] = True

        consent = self.client.post(
            "/integrations/secure-chat/authorize",
            data={"state": "secure-chat-state-123456", "consent": "yes"},
        )
        self.assertEqual(consent.status_code, 302)
        code = parse_qs(urlsplit(consent.location).query)["code"][0]
        self.assertTrue(
            db.session.get(User, self.user.id).secure_chat_enabled,
            f"Consent redirect was {consent.location}",
        )
        stored_code = SecureChatAuthorizationCode.query.one()
        self.assertEqual(stored_code.user_id, self.user.id)
        exchange = self.client.post(
            "/api/secure-chat/v1/token",
            json={"code": code},
            headers=self._service_headers(),
        )
        self.assertEqual(exchange.status_code, 200, exchange.get_json())
        return code, exchange.get_json()["access_token"]

    def test_service_key_is_required(self):
        response = self.client.post(
            "/api/secure-chat/v1/detect",
            json={"type": "message", "text": "hello"},
        )
        self.assertEqual(response.status_code, 401)

    def test_consent_page_includes_csrf_token(self):
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.user.id)
            session["_fresh"] = True
        response = self.client.get(
            "/integrations/secure-chat/authorize?state=secure-chat-state-123456"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="csrf_token"', response.data)

    def test_account_token_is_required_after_service_auth(self):
        response = self.client.post(
            "/api/secure-chat/v1/detect",
            json={"type": "message", "text": "hello"},
            headers=self._service_headers(),
        )
        self.assertEqual(response.status_code, 401)

    def test_consent_exchange_is_single_use_and_revocation_is_immediate(self):
        code, token = self._enable_and_exchange()
        replay = self.client.post(
            "/api/secure-chat/v1/token",
            json={"code": code},
            headers=self._service_headers(),
        )
        self.assertEqual(replay.status_code, 401)

        self.user.secure_chat_enabled = False
        db.session.commit()
        response = self.client.post(
            "/api/secure-chat/v1/detect",
            json={"type": "unsupported"},
            headers={
                **self._service_headers(),
                "Authorization": f"Bearer {token}",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_valid_link_reaches_detection_type_validation(self):
        _, token = self._enable_and_exchange()
        response = self.client.post(
            "/api/secure-chat/v1/detect",
            json={"type": "unsupported"},
            headers={
                **self._service_headers(),
                "Authorization": f"Bearer {token}",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["error"],
            "type must be message, url, upi, qr, image, or voice",
        )

    def test_real_detectors_return_normalized_results_and_account_attribution(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        detections = [
            {"type": "message", "text": "Your order has shipped and will arrive tomorrow."},
            {"type": "url", "url": "https://www.google.com"},
            {"type": "upi", "upi_id": "alice@okaxis", "amount": 100, "note": "invoice"},
        ]

        for payload in detections:
            with self.subTest(detection_type=payload["type"]):
                response = self.client.post(
                    "/api/secure-chat/v1/detect",
                    json=payload,
                    headers=headers,
                )
                self.assertEqual(response.status_code, 200, response.get_json())
                result = response.get_json()
                self.assertIn(result["verdict"], {"Safe", "Suspicious", "Scam"})
                self.assertIn(result["classification"], {"SAFE", "SUSPICIOUS", "SCAM"})
                self.assertEqual(result["type"], {"message": "text"}.get(payload["type"], payload["type"]))
                self.assertEqual(result["language"], "en")
                self.assertTrue(result["scan_id"])
                self.assertGreaterEqual(result["confidence"], 0)
                self.assertLessEqual(result["confidence"], 100)
                self.assertGreaterEqual(result["risk_score"], 0)
                self.assertLessEqual(result["risk_score"], 100)
                record = db.session.get(ScanHistory, result["scan_id"])
                self.assertIsNotNone(record)
                self.assertEqual(record.verdict, result["classification"].lower())
                self.assertEqual(record.source, "secure-chat")
                self.assertEqual(record.user_id, self.user.id)
                self.assertIn(
                    result["detection_type"],
                    {"SMS/DistilBERT", "URL/XGBoost", "UPI GNN + XGBoost"},
                )
                self.assertIn("explanation", result)
                self.assertIn("localized", result)

        records = ScanHistory.query.filter_by(
            user_id=self.user.id,
            source="secure-chat",
        ).all()
        self.assertEqual({record.scan_type for record in records}, {"message", "url", "upi"})

    def test_message_detection_returns_displayable_warning_state(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }

        for verdict, should_warn in (("scam", True), ("suspicious", True), ("safe", False)):
            with self.subTest(verdict=verdict):
                with patch(
                    "backend.routes.secure_chat.classify_message",
                    return_value={
                        "engine": "DistilBERT",
                        "verdict": verdict,
                        "confidence": 91.0,
                        "risk": 80.0 if should_warn else 2.0,
                        "reasons": ["Test reason"],
                        "tips": ["Test action"],
                    },
                ):
                    response = self.client.post(
                        "/api/secure-chat/v1/detect",
                        json={"type": "message", "text": "Test message"},
                        headers=headers,
                    )

                self.assertEqual(response.status_code, 200, response.get_json())
                result = response.get_json()
                self.assertTrue(result["success"])
                self.assertEqual(result["prediction"], verdict.upper())
                self.assertEqual(result["should_warn"], should_warn)
                self.assertEqual(result["localized"]["should_warn"], should_warn)
                if should_warn:
                    self.assertTrue(result["alert"])
                    self.assertEqual(result["localized"]["alert"], result["alert"])
                    alert_prefix = "warning" if verdict == "scam" else "caution"
                    self.assertTrue(result["alert"].lower().startswith(alert_prefix))
                else:
                    self.assertIsNone(result["alert"])
                    self.assertIsNone(result["localized"]["alert"])

    def test_image_detection_runs_ocr_and_returns_image_alert(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        classification = {
            "engine": "DistilBERT",
            "verdict": "scam",
            "confidence": 96.0,
            "risk": 94.0,
            "reasons": ["Test image reason"],
            "tips": ["Test image action"],
        }
        with patch(
            "backend.routes.secure_chat._detect_image_for_sc",
            return_value=(classification, {"analysis_type": "image-text", "content": "Urgent account warning"}),
        ):
            response = self.client.post(
                "/api/secure-chat/v1/detect",
                data={
                    "type": "image",
                    "image": (BytesIO(b"image bytes"), "message.png"),
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assertEqual(result["detection_type"], "SMS/DistilBERT")
        self.assertEqual(result["analysis_type"], "image-text")
        self.assertTrue(result["should_warn"])
        self.assertEqual(result["classification"], "SCAM")
        self.assertEqual(result["type"], "image")
        self.assertTrue(result["scan_id"])
        self.assertIn("image", result["alert"].lower())
        record = db.session.get(ScanHistory, result["scan_id"])
        self.assertEqual(record.verdict, "scam")
        self.assertEqual(record.scan_type, "screenshot")

    def test_voice_detection_transcribes_and_returns_voice_alert(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        classification = {
            "engine": "DistilBERT",
            "verdict": "suspicious",
            "confidence": 88.0,
            "risk": 61.0,
            "reasons": ["Test voice reason"],
            "tips": ["Test voice action"],
        }
        with patch(
            "backend.routes.secure_chat.transcribe_audio",
            return_value=("Please transfer money to secure your account", None),
        ), patch("backend.routes.secure_chat.classify_message", return_value=classification):
            response = self.client.post(
                "/api/secure-chat/v1/detect",
                data={
                    "type": "voice",
                    "audio": (BytesIO(b"audio bytes"), "voice.wav"),
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assertEqual(result["detection_type"], "Whisper + DistilBERT")
        self.assertEqual(result["analysis_type"], "voice-transcription")
        self.assertEqual(result["transcription"], "Please transfer money to secure your account")
        self.assertTrue(result["should_warn"])
        self.assertEqual(result["classification"], "SUSPICIOUS")
        self.assertEqual(result["type"], "voice")
        self.assertTrue(result["scan_id"])
        self.assertIn("voice message", result["alert"].lower())
        record = db.session.get(ScanHistory, result["scan_id"])
        self.assertEqual(record.verdict, "suspicious")
        self.assertEqual(record.scan_type, "voice")

    def test_qr_detection_returns_normalized_result_and_saves_history(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        classification = {
            "engine": "url",
            "verdict": "scam",
            "confidence": 93.0,
            "risk": 91.0,
            "reasons": ["Test QR reason"],
            "tips": ["Test QR action"],
        }
        with patch(
            "backend.routes.secure_chat._detect_qr_for_sc",
            return_value=(classification, {
                "analysis_type": "qr-url",
                "decoded_content": "https://example.test/login",
                "content": "https://example.test/login",
            }),
        ):
            response = self.client.post(
                "/api/secure-chat/v1/detect",
                data={
                    "type": "qr",
                    "image": (BytesIO(b"image bytes"), "qr.png"),
                    "language": "en",
                },
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assertEqual(result["type"], "qr")
        self.assertEqual(result["classification"], "SCAM")
        self.assertEqual(result["language"], "en")
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertTrue(result["scan_id"])
        self.assertEqual(result["analysis_type"], "qr-url")
        record = db.session.get(ScanHistory, result["scan_id"])
        self.assertEqual(record.verdict, "scam")
        self.assertEqual(record.scan_type, "qr")

    def test_scan_persistence_failure_returns_server_error(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        with patch(
            "backend.routes.secure_chat.classify_message",
            return_value={
                "engine": "DistilBERT",
                "verdict": "safe",
                "confidence": 99.0,
                "risk": 1.0,
                "reasons": [],
                "tips": [],
            },
        ), patch.object(db.session, "commit", side_effect=RuntimeError("database unavailable")):
            response = self.client.post(
                "/api/secure-chat/v1/detect",
                json={"type": "message", "text": "hello"},
                headers=headers,
            )

        self.assertEqual(response.status_code, 500)
        self.assertIn("error", response.get_json())

    def test_detected_script_language_is_returned_and_used_for_alert(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        with patch(
            "backend.routes.secure_chat.classify_message",
            return_value={
                "engine": "DistilBERT",
                "verdict": "scam",
                "confidence": 95.0,
                "risk": 92.0,
                "reasons": [],
                "tips": [],
            },
        ), patch("backend.routes.secure_chat.to_english", return_value="English text"), patch(
            "backend.routes.secure_chat.translate",
            side_effect=lambda text, language: f"{language}:{text}",
        ):
            response = self.client.post(
                "/api/secure-chat/v1/detect",
                json={"type": "message", "text": "आपका खाता बंद हो जाएगा"},
                headers=headers,
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assertEqual(result["language"], "hi")
        self.assertTrue(result["alert"].startswith("hi:"))
        self.assertEqual(result["localized"]["language"], "hi")

    def test_slow_translation_provider_falls_back_without_blocking(self):
        from backend.utils.localization import translate_text

        phrase = "यह धीमे अनुवाद प्रदाता का परीक्षण है"

        class SlowTranslator:
            def translate(self, _text):
                time.sleep(0.1)
                return "translated"

        translate_text.cache_clear()
        with patch("deep_translator.GoogleTranslator", return_value=SlowTranslator()), patch(
            "deep_translator.MyMemoryTranslator", return_value=SlowTranslator()
        ), patch("backend.utils.localization._TRANSLATION_TIMEOUT_SECONDS", 0.01):
            translated = translate_text(phrase, "hi", "en")

        self.assertEqual(translated, phrase)

    def test_url_and_upi_alerts_name_the_detected_content(self):
        _, token = self._enable_and_exchange()
        headers = {
            **self._service_headers(),
            "Authorization": f"Bearer {token}",
        }
        suspicious = {
            "engine": "test-detector",
            "verdict": "suspicious",
            "confidence": 84.0,
            "risk": 57.0,
            "reasons": ["Test reason"],
            "tips": ["Test action"],
        }
        cases = (
            ({"type": "url", "url": "https://example.com"}, "classify_url", "url"),
            (
                {"type": "upi", "upi_id": "alice@okaxis", "amount": 25},
                "classify_upi",
                "upi payment request",
            ),
        )
        for payload, classifier, label in cases:
            with self.subTest(detection_type=payload["type"]):
                with patch(f"backend.routes.secure_chat.{classifier}", return_value=suspicious):
                    response = self.client.post(
                        "/api/secure-chat/v1/detect",
                        json=payload,
                        headers=headers,
                    )

                self.assertEqual(response.status_code, 200, response.get_json())
                result = response.get_json()
                self.assertTrue(result["success"])
                self.assertEqual(result["classification"], "SUSPICIOUS")
                self.assertEqual(result["type"], payload["type"])
                self.assertTrue(result["scan_id"])
                self.assertTrue(result["should_warn"])
                self.assertIn(label, result["alert"].lower())
                self.assertEqual(result["localized"]["alert"], result["alert"])
                record = db.session.get(ScanHistory, result["scan_id"])
                self.assertEqual(record.verdict, "suspicious")
                self.assertEqual(record.scan_type, payload["type"])


if __name__ == "__main__":
    unittest.main()