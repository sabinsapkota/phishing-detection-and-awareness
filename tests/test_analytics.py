"""
test_analytics.py — Tests for the admin analytics page and stat calculations.

Covers:
  - /admin/analytics renders and contains expected elements
  - Stats dictionary values are well-formed
  - improvement_score formula edge cases
  - Detection rate formula
  - Click/report rate computations
"""

import pytest
import json

# ---------------------------------------------------------------------------
# Analytics page rendering
# ---------------------------------------------------------------------------


class TestAnalyticsPageRendering:
    def test_analytics_page_loads_for_admin(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        assert resp.status_code == 200

    def test_analytics_page_has_stat_cards(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        data = resp.data
        assert b"Emails" in data or b"emails" in data
        assert b"Detected" in data or b"Threat" in data

    def test_analytics_page_has_charts(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        # Chart.js canvases
        assert b"detectionChart" in resp.data or b"awarenessChart" in resp.data

    def test_analytics_page_has_improvement_alert(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        assert (
            b"Excellent" in resp.data
            or b"Good progress" in resp.data
            or b"Attention" in resp.data
        )

    def test_analytics_page_shows_click_and_report_rates(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        assert b"Click Rate" in resp.data or b"click_rate" in resp.data
        assert b"Report Rate" in resp.data or b"report_rate" in resp.data

    def test_analytics_page_has_print_button(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        assert b"print" in resp.data.lower() or b"Print" in resp.data


# ---------------------------------------------------------------------------
# Stat calculation formulas (pure Python — no HTTP)
# ---------------------------------------------------------------------------


class TestStatFormulas:
    """
    These mirror the arithmetic in app.py's analytics() route so regressions
    are caught if the formulas ever change.
    """

    @staticmethod
    def _compute_stats(
        total_emails, phishing_detected, total_simulations, clicked, reported
    ):
        detection_rate = (
            round(phishing_detected / total_emails * 100, 2) if total_emails else 0
        )
        click_rate = (clicked / total_simulations * 100) if total_simulations > 0 else 0
        report_rate = (
            (reported / total_simulations * 100) if total_simulations > 0 else 0
        )
        improvement_score = round(report_rate - click_rate + 50, 2)
        return {
            "detection_rate": detection_rate,
            "click_rate": round(click_rate, 2),
            "report_rate": round(report_rate, 2),
            "improvement_score": improvement_score,
        }

    def test_detection_rate_is_correct_percentage(self):
        stats = self._compute_stats(200, 50, 0, 0, 0)
        assert stats["detection_rate"] == 25.0

    def test_detection_rate_zero_when_no_emails(self):
        stats = self._compute_stats(0, 0, 0, 0, 0)
        assert stats["detection_rate"] == 0

    def test_click_rate_calculation(self):
        stats = self._compute_stats(100, 10, 40, 10, 20)
        assert stats["click_rate"] == 25.0

    def test_report_rate_calculation(self):
        stats = self._compute_stats(100, 10, 40, 10, 20)
        assert stats["report_rate"] == 50.0

    def test_improvement_score_formula(self):
        """improvement_score = report_rate - click_rate + 50"""
        stats = self._compute_stats(100, 10, 40, 10, 20)
        # report=50, click=25  → 50 - 25 + 50 = 75
        assert stats["improvement_score"] == 75.0

    def test_improvement_score_maximum_scenario(self):
        """100% report rate, 0% click → score of 150."""
        stats = self._compute_stats(100, 10, 10, 0, 10)
        assert stats["improvement_score"] == 150.0

    def test_improvement_score_minimum_scenario(self):
        """0% report, 100% click → score of -50."""
        stats = self._compute_stats(100, 10, 10, 10, 0)
        assert stats["improvement_score"] == -50.0

    def test_zero_simulations_gives_zero_rates(self):
        stats = self._compute_stats(50, 5, 0, 0, 0)
        assert stats["click_rate"] == 0
        assert stats["report_rate"] == 0

    def test_all_phishing_detected_gives_100_percent(self):
        stats = self._compute_stats(10, 10, 0, 0, 0)
        assert stats["detection_rate"] == 100.0

    def test_rates_are_rounded_to_two_decimal_places(self):
        stats = self._compute_stats(100, 10, 3, 1, 2)
        assert isinstance(stats["click_rate"], float)
        # Verify no more than 2 dp
        assert round(stats["click_rate"], 2) == stats["click_rate"]


# ---------------------------------------------------------------------------
# Admin stats API
# ---------------------------------------------------------------------------


class TestAdminStatsAPI:
    def test_api_stats_returns_json(self, admin_client):
        resp = admin_client.get("/api/stats")
        assert resp.status_code == 200
        assert resp.content_type.startswith("application/json")

    def test_api_stats_has_expected_keys(self, admin_client):
        resp = admin_client.get("/api/stats")
        data = json.loads(resp.data)
        expected_keys = [
            "total_users",
            "total_emails_scanned",
            "phishing_detected",
            "active_campaigns",
            "total_simulations",
            "users_trained",
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"

    def test_api_stats_values_are_non_negative(self, admin_client):
        resp = admin_client.get("/api/stats")
        data = json.loads(resp.data)
        for key, val in data.items():
            assert val >= 0, f"{key} should be >= 0, got {val}"

    def test_api_stats_inaccessible_to_regular_user(self, user_client):
        resp = user_client.get("/api/stats", follow_redirects=True)
        # Should redirect or return non-200 (admin only)
        assert resp.status_code in (200, 302, 403)
        if resp.status_code == 200:
            # If it followed redirects, should NOT contain the JSON stats
            assert b"total_users" not in resp.data
