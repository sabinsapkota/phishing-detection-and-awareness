"""
test_detection.py — Tests for the /detect route and get_ml_reasoning().

Covers:
  - GET /detect renders the form
  - POST /detect with simple and full-email input modes
  - Risk-level banding logic
  - ML reasoning messages for phishing vs legitimate emails
  - Empty / missing input handling
  - API endpoint /api/detect
"""

import pytest
import json

# ---------------------------------------------------------------------------
# GET /detect
# ---------------------------------------------------------------------------


class TestDetectPage:
    def test_detect_page_renders(self, user_client):
        resp = user_client.get("/detect")
        assert resp.status_code == 200
        assert b"Detection" in resp.data or b"Phishing" in resp.data

    def test_detect_page_has_both_input_tabs(self, user_client):
        resp = user_client.get("/detect")
        assert b"Full Email" in resp.data or b"full" in resp.data
        assert b"Simple" in resp.data or b"simple" in resp.data

    def test_detect_page_shows_detection_features(self, user_client):
        resp = user_client.get("/detect")
        assert b"URL" in resp.data or b"Header" in resp.data


# ---------------------------------------------------------------------------
# POST /detect — simple mode
# ---------------------------------------------------------------------------


class TestDetectSimpleMode:
    def _post_simple(self, client, sender="", subject="", content=""):
        return client.post(
            "/detect",
            data={
                "input_type": "simple",
                "sender": sender,
                "subject": subject,
                "content": content,
            },
            follow_redirects=True,
        )

    def test_legitimate_email_returns_result_page(self, user_client):
        resp = self._post_simple(
            user_client,
            sender="news@github.com",
            subject="Your weekly digest",
            content="Here are the highlights from the repos you follow this week.",
        )
        assert resp.status_code == 200
        assert (
            b"Detection Result" in resp.data
            or b"LEGITIMATE" in resp.data
            or b"Confidence" in resp.data
        )

    def test_phishing_email_returns_result_page(self, user_client):
        resp = self._post_simple(
            user_client,
            sender="security@amaz0n-security.tk",
            subject="URGENT: Verify your account NOW!!!",
            content=(
                "Click here immediately to verify your account or it will be suspended. "
                "Your password must be reset. http://192.168.1.1/reset"
            ),
        )
        assert resp.status_code == 200
        # Result page should contain risk indicators
        assert b"Confidence" in resp.data or b"Risk" in resp.data

    def test_empty_content_does_not_crash(self, user_client):
        resp = self._post_simple(user_client, sender="x@x.com", subject="", content="")
        # Should not 500 — either flash an error or show result
        assert resp.status_code != 500

    def test_result_page_shows_feature_breakdown(self, user_client):
        resp = self._post_simple(
            user_client,
            sender="sender@example.com",
            subject="Hello",
            content="Just a normal message.",
        )
        assert resp.status_code == 200
        # Feature breakdown section should appear
        assert (
            b"Feature" in resp.data
            or b"URLs Found" in resp.data
            or b"Urgent" in resp.data
        )


# ---------------------------------------------------------------------------
# POST /detect — full-email mode
# ---------------------------------------------------------------------------

FULL_EMAIL_LEGIT = """\
From: newsletter@github.com
To: user@example.com
Subject: Your GitHub digest
Date: Mon, 01 Jan 2024 10:00:00 +0000

Hi there,
Here is your weekly digest.
No action required.
"""

FULL_EMAIL_PHISH = """\
From: security@paypa1-verify.net
To: victim@company.com
Subject: URGENT: Your PayPal account has been LIMITED!!!
Date: Tue, 02 Jan 2024 09:00:00 +0000

Dear customer,
We have detected suspicious activity. Click now to verify: http://paypa1.xyz/login
Act IMMEDIATELY or your account will be suspended.
"""


class TestDetectFullMode:
    def _post_full(self, client, email_text):
        return client.post(
            "/detect",
            data={"input_type": "full", "full_email": email_text},
            follow_redirects=True,
        )

    def test_full_legitimate_email_shows_result(self, user_client):
        resp = self._post_full(user_client, FULL_EMAIL_LEGIT)
        assert resp.status_code == 200
        assert b"Confidence" in resp.data or b"Risk" in resp.data

    def test_full_phishing_email_shows_result(self, user_client):
        resp = self._post_full(user_client, FULL_EMAIL_PHISH)
        assert resp.status_code == 200
        assert b"Confidence" in resp.data or b"Risk" in resp.data

    def test_empty_full_email_shows_error(self, user_client):
        resp = self._post_full(user_client, "   ")
        assert resp.status_code == 200
        assert (
            b"Please" in resp.data
            or b"paste" in resp.data.lower()
            or b"error" in resp.data.lower()
        )

    def test_parsed_from_appears_in_result(self, user_client):
        resp = self._post_full(user_client, FULL_EMAIL_LEGIT)
        assert resp.status_code == 200
        # Sender domain should appear somewhere in result
        assert (
            b"github" in resp.data or b"newsletter" in resp.data or b"From" in resp.data
        )


# ---------------------------------------------------------------------------
# Risk-level banding (unit-level — no HTTP)
# ---------------------------------------------------------------------------


class TestRiskLevelBanding:
    """
    Directly test the risk-level logic extracted from app.py:
        HIGH   >= 0.65
        MEDIUM >= 0.50
        LOW    <  0.50
    """

    @staticmethod
    def _risk(confidence):
        return (
            "HIGH" if confidence >= 0.65 else "MEDIUM" if confidence >= 0.5 else "LOW"
        )

    def test_confidence_above_threshold_is_high(self):
        assert self._risk(0.65) == "HIGH"
        assert self._risk(0.80) == "HIGH"
        assert self._risk(1.00) == "HIGH"

    def test_confidence_in_medium_band(self):
        assert self._risk(0.50) == "MEDIUM"
        assert self._risk(0.60) == "MEDIUM"
        assert self._risk(0.64) == "MEDIUM"

    def test_confidence_below_medium_is_low(self):
        assert self._risk(0.49) == "LOW"
        assert self._risk(0.00) == "LOW"

    def test_boundary_values(self):
        # Exact threshold boundary
        assert self._risk(0.649) == "MEDIUM"
        assert self._risk(0.650) == "HIGH"


# ---------------------------------------------------------------------------
# ML Reasoning (unit-level)
# ---------------------------------------------------------------------------


class TestMLReasoning:
    @pytest.fixture(autouse=True)
    def _import(self):
        from app import get_ml_reasoning

        self.reasoning = get_ml_reasoning

    def test_phishing_multiple_urls_reason(self):
        feats = {
            "num_urls": 5,
            "urgent_words_count": 3,
            "has_ip_in_url": 0,
            "suspicious_tld_count": 0,
            "header_mismatch": 0,
            "exclamation_count": 0,
            "capital_ratio": 0.1,
            "has_attachments": 0,
        }
        reasons = self.reasoning(feats, True, 0.90)
        assert any("link" in r.lower() or "url" in r.lower() for r in reasons)

    def test_phishing_ip_url_reason(self):
        feats = {
            "num_urls": 1,
            "urgent_words_count": 0,
            "has_ip_in_url": 1,
            "suspicious_tld_count": 0,
            "header_mismatch": 0,
            "exclamation_count": 0,
            "capital_ratio": 0.1,
            "has_attachments": 0,
        }
        reasons = self.reasoning(feats, True, 0.90)
        assert any("ip" in r.lower() or "IP" in r for r in reasons)

    def test_phishing_high_exclamation_reason(self):
        feats = {
            "num_urls": 0,
            "urgent_words_count": 0,
            "has_ip_in_url": 0,
            "suspicious_tld_count": 0,
            "header_mismatch": 0,
            "exclamation_count": 8,
            "capital_ratio": 0.1,
            "has_attachments": 0,
        }
        reasons = self.reasoning(feats, True, 0.90)
        assert any("exclamation" in r.lower() for r in reasons)

    def test_legitimate_email_has_no_strong_indicator_reason(self):
        feats = {
            "num_urls": 0,
            "urgent_words_count": 0,
            "has_ip_in_url": 0,
            "suspicious_tld_count": 0,
            "header_mismatch": 0,
            "exclamation_count": 0,
            "capital_ratio": 0.05,
            "has_attachments": 0,
            "legitimate_esp_sending_pattern": 0,
            "dkim_passes_for_from_domain": 0,
        }
        reasons = self.reasoning(feats, False, 0.10)
        assert any("no strong" in r.lower() or "no" in r.lower() for r in reasons)

    def test_non_dict_features_does_not_crash(self):
        """get_ml_reasoning handles non-dict gracefully."""
        reasons = self.reasoning(None, False, 0.10)
        assert isinstance(reasons, list)

    def test_returns_list_always(self):
        feats = {}
        reasons = self.reasoning(feats, True, 0.80)
        assert isinstance(reasons, list)
        assert len(reasons) >= 1


# ---------------------------------------------------------------------------
# API endpoint /api/detect
# ---------------------------------------------------------------------------


class TestAPIDetect:
    def test_api_detect_missing_body_returns_400(self, user_client):
        resp = user_client.post(
            "/api/detect",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = json.loads(resp.data)
        assert "error" in data

    def test_api_detect_with_content_returns_json(self, user_client):
        # Without a real model loaded the endpoint returns 500,
        # which is still valid JSON — just test the response is JSON.
        resp = user_client.post(
            "/api/detect",
            data=json.dumps({"email": "From: x@x.com\n\nHello"}),
            content_type="application/json",
        )
        assert resp.content_type.startswith("application/json")
