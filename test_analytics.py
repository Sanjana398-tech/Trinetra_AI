import unittest
from datetime import datetime, timedelta

from backend import create_app
from backend.db_models import ScanHistory, User
from backend.extensions import db
from backend.utils.analytics_query import (
    build_overview,
    build_summary,
    filtered_query,
    parse_filters,
)


class AnalyticsQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app("testing")
        cls.context = cls.app.app_context()
        cls.context.push()
        db.drop_all()
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        cls.context.pop()

    def setUp(self):
        db.session.query(ScanHistory).delete()
        db.session.query(User).delete()
        db.session.commit()

        self.user = User(
            full_name="Analytics Tester",
            email="analytics-test@example.com",
            password_hash="test",
        )
        db.session.add(self.user)
        db.session.flush()

        now = datetime.utcnow()
        self.range_start = (now - timedelta(days=2)).strftime("%Y-%m-%d")
        self.range_end = now.strftime("%Y-%m-%d")
        db.session.add_all(
            [
                ScanHistory(
                    user_id=self.user.id,
                    scan_type="message",
                    input_summary="safe message",
                    verdict="safe",
                    risk_score=5,
                    created_at=now,
                ),
                ScanHistory(
                    user_id=self.user.id,
                    scan_type="url",
                    input_summary="scam url",
                    verdict="scam",
                    risk_score=95,
                    created_at=now - timedelta(days=2),
                ),
                ScanHistory(
                    user_id=self.user.id,
                    scan_type="voice",
                    input_summary="suspicious call",
                    verdict="suspicious",
                    risk_score=60,
                    created_at=now - timedelta(days=2),
                ),
            ]
        )
        db.session.commit()

    def test_summary_uses_sql_filtered_scan_history(self):
        filters = parse_filters(
            {"range": "custom", "start": self.range_start, "end": self.range_end}
        )
        summary = build_summary(filtered_query(self.user, filters))

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["safe"], 1)
        self.assertEqual(summary["suspicious"], 1)
        self.assertEqual(summary["scam"], 1)
        self.assertEqual(summary["detectionRate"], 66.7)

    def test_type_and_verdict_filters_change_summary(self):
        filters = parse_filters({"range": "all", "type": "url", "verdict": "scam"})
        summary = build_summary(filtered_query(self.user, filters))

        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["scam"], 1)
        self.assertEqual(summary["safe"], 0)

    def test_overview_contains_all_chart_and_table_payloads(self):
        payload = build_overview(self.user, {"range": "all"})

        self.assertEqual(payload["summary"]["total"], 3)
        self.assertIn("timeline", payload)
        self.assertIn("byType", payload)
        self.assertIn("byVerdict", payload)
        self.assertIn("scamByType", payload)
        self.assertIn("typeDate", payload)
        self.assertIn("recentThreats", payload)
        self.assertIn("table", payload)


if __name__ == "__main__":
    unittest.main()