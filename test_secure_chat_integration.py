import unittest
from urllib.parse import parse_qs, urlsplit
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
        self.assertEqual(response.get_json()["error"], "type must be message, url, or upi")

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
                self.assertGreaterEqual(result["confidence"], 0)
                self.assertLessEqual(result["confidence"], 100)
                self.assertGreaterEqual(result["risk_score"], 0)
                self.assertLessEqual(result["risk_score"], 100)
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
                self.assertEqual(result["should_warn"], should_warn)
                self.assertEqual(result["localized"]["should_warn"], should_warn)
                if should_warn:
                    self.assertTrue(result["alert"])
                    self.assertEqual(result["localized"]["alert"], result["alert"])
                else:
                    self.assertIsNone(result["alert"])
                    self.assertIsNone(result["localized"]["alert"])


if __name__ == "__main__":
    unittest.main()