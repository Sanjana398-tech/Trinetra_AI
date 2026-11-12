import unittest
from datetime import datetime

from backend import create_app
from backend.db_models import ScanHistory, User
from backend.extensions import db


class UniversalDashboardTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        ScanHistory.query.delete()
        User.query.delete()
        db.session.commit()

        self.first_user = User(full_name="First Account", email="first@example.com", password_hash="test")
        self.second_user = User(full_name="Second Account", email="second@example.com", password_hash="test")
        db.session.add_all([self.first_user, self.second_user])
        db.session.flush()
        db.session.add_all([
            ScanHistory(user_id=self.first_user.id, scan_type="message", input_summary="PRIVATE MESSAGE SECRET", verdict="safe", risk_score=2, created_at=datetime.utcnow()),
            ScanHistory(user_id=self.first_user.id, scan_type="url", input_summary="https://private.example/secret", verdict="scam", risk_score=99, created_at=datetime.utcnow()),
            ScanHistory(user_id=self.second_user.id, scan_type="upi", input_summary="private@upi", verdict="suspicious", risk_score=60, created_at=datetime.utcnow()),
            ScanHistory(user_id=self.second_user.id, scan_type="qr", input_summary="private qr contents", verdict="safe", risk_score=1, source="secure-chat", created_at=datetime.utcnow()),
        ])
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.first_user.id)
            session["_fresh"] = True

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def test_authenticated_user_sees_aggregate_dashboard_and_api(self):
        page = self.client.get("/universal-security")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Universal Security Dashboard", page.data)
        response = self.client.get("/api/universal-security/overview?range=all")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["summary"], {
            "registeredUsers": 2,
            "totalScans": 4,
            "safe": 2,
            "suspicious": 1,
            "scam": 1,
            "scamPercentage": 25.0,
        })
        channels = {item["key"]: item["count"] for item in payload["channels"]}
        self.assertEqual(channels["message"], 1)
        self.assertEqual(channels["url"], 1)
        self.assertEqual(channels["upi"], 1)
        self.assertEqual(channels["qr"], 1)
        self.assertEqual(channels["secure-chat"], 1)

    def test_api_contains_aggregates_only(self):
        response = self.client.get("/api/universal-security/overview?range=all")
        response_text = response.get_data(as_text=True)
        self.assertNotIn("PRIVATE MESSAGE SECRET", response_text)
        self.assertNotIn("private.example", response_text)
        self.assertNotIn("private@upi", response_text)
        self.assertNotIn("First Account", response_text)
        self.assertNotIn("first@example.com", response_text)
        self.assertNotIn("input_summary", response_text)
        self.assertNotIn("username", response_text)

    def test_unauthenticated_user_is_redirected(self):
        client = self.app.test_client()
        self.assertEqual(client.get("/universal-security").status_code, 302)
        self.assertEqual(client.get("/api/universal-security/overview").status_code, 302)

    def test_date_filters_and_invalid_custom_range(self):
        today = datetime.utcnow().date().isoformat()
        response = self.client.get("/api/universal-security/overview?range=today")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["filters"]["start"], today)
        invalid = self.client.get("/api/universal-security/overview?range=custom&start=nope&end=nope")
        self.assertEqual(invalid.status_code, 400)


if __name__ == "__main__":
    unittest.main()