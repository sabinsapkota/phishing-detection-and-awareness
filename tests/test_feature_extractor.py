"""
test_feature_extractor.py — Unit tests for EnhancedFeatureExtractor.

Tests that the feature dictionary produced by extract_features() correctly
reflects the content of a parsed email.  All tests are pure Python — no HTTP
calls, no database.
"""

import pytest
import sys
import os

# Ensure the project root is on the path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from email_parser import FullEmailParser, EnhancedFeatureExtractor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parsed(
    from_="sender@example.com",
    subject="Hello",
    body_plain="Normal body",
    body_html="",
    header_mismatch=None,
    attachments=None,
):
    return {
        "from": from_,
        "subject": subject,
        "body_plain": body_plain,
        "body_html": body_html or "",
        "header_mismatch": header_mismatch or [],
        "attachments": attachments or [],
    }


@pytest.fixture(scope="module")
def extractor():
    return EnhancedFeatureExtractor()


# ---------------------------------------------------------------------------
# URL features
# ---------------------------------------------------------------------------


class TestURLFeatures:
    def test_no_urls_gives_zero_count(self, extractor):
        feats, _ = extractor.extract_features(_parsed(body_plain="No links here."))
        assert feats["url_count"] == 0

    def test_url_count_matches_links_in_body(self, extractor):
        body = "Go to http://example.com and also https://another.org please."
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["url_count"] == 2

    def test_ip_address_url_detected(self, extractor):
        body = "Click http://192.168.1.1/malware to continue."
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["has_ip_url"] == 1

    def test_normal_url_not_flagged_as_ip(self, extractor):
        body = "Visit https://google.com for more."
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["has_ip_url"] == 0

    def test_suspicious_tld_detected(self, extractor):
        body = "Download from http://free-stuff.tk/file"
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["has_suspicious_tld"] == 1

    def test_safe_tld_not_flagged(self, extractor):
        body = "Visit https://github.com/project"
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["has_suspicious_tld"] == 0

    def test_urls_returned_in_second_element(self, extractor):
        body = "Go to http://example.com now."
        _, urls = extractor.extract_features(_parsed(body_plain=body))
        assert isinstance(urls, list)
        assert any("example.com" in u for u in urls)


# ---------------------------------------------------------------------------
# Content / urgency features
# ---------------------------------------------------------------------------


class TestContentFeatures:
    def test_urgent_word_detected(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(body_plain="URGENT: verify your account immediately!")
        )
        assert feats["has_urgent_words"] == 1
        assert feats["urgent_word_count"] >= 1

    def test_no_urgency_in_normal_email(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(body_plain="Just a friendly update. Have a great day!")
        )
        assert feats["has_urgent_words"] == 0

    def test_exclamation_count_accurate(self, extractor):
        body = "Warning! Act now! Limited time!"
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["exclamation_count"] == 3

    def test_dollar_sign_counted(self, extractor):
        body = "You could win $1000 or even $5000 today!"
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["dollar_count"] == 2

    def test_capital_ratio_high_for_all_caps(self, extractor):
        body = "CLICK NOW OR YOUR ACCOUNT WILL BE DELETED"
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["capital_ratio"] > 0.5

    def test_capital_ratio_low_for_normal_text(self, extractor):
        body = "Please review our terms of service at your convenience."
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["capital_ratio"] < 0.2

    def test_body_length_reflects_content(self, extractor):
        body = "Short."
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["body_length"] == len(body)

    def test_subject_length_reflects_content(self, extractor):
        subject = "Important security update"
        feats, _ = extractor.extract_features(_parsed(subject=subject))
        assert feats["subject_length"] == len(subject)

    def test_suspicious_words_counted(self, extractor):
        body = "Please verify your account and confirm your password."
        feats, _ = extractor.extract_features(_parsed(body_plain=body))
        assert feats["has_suspicious_words"] == 1
        assert feats["suspicious_word_count"] >= 2

    def test_subject_all_caps_flag(self, extractor):
        feats, _ = extractor.extract_features(_parsed(subject="URGENT SECURITY ALERT"))
        assert feats["subject_all_caps"] == 1

    def test_subject_exclamation_flag(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(subject="Your account is at risk!")
        )
        assert feats["subject_exclamation"] == 1


# ---------------------------------------------------------------------------
# Sender features
# ---------------------------------------------------------------------------


class TestSenderFeatures:
    def test_sender_with_numbers_flagged(self, extractor):
        feats, _ = extractor.extract_features(_parsed(from_="security1234@examp1e.com"))
        assert feats["sender_has_numbers"] == 1

    def test_clean_sender_not_flagged_for_numbers(self, extractor):
        feats, _ = extractor.extract_features(_parsed(from_="info@legitimatebank.com"))
        assert feats["sender_has_numbers"] == 0

    def test_disposable_domain_detected(self, extractor):
        feats, _ = extractor.extract_features(_parsed(from_="user@mailinator.com"))
        assert feats["sender_disposable"] == 1

    def test_normal_domain_not_disposable(self, extractor):
        feats, _ = extractor.extract_features(_parsed(from_="info@microsoft.com"))
        assert feats["sender_disposable"] == 0


# ---------------------------------------------------------------------------
# HTML / attachment features
# ---------------------------------------------------------------------------


class TestHTMLAndAttachmentFeatures:
    def test_html_body_detected(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(body_html="<p>Click <a href='http://x.com'>here</a></p>")
        )
        assert feats["has_html"] == 1

    def test_plain_text_not_flagged_as_html(self, extractor):
        feats, _ = extractor.extract_features(_parsed(body_plain="Just text."))
        assert feats["has_html"] == 0

    def test_form_in_body_detected(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(body_html="<form action='steal.php'><input type='password'></form>")
        )
        assert feats["has_forms"] == 1

    def test_script_in_body_detected(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(body_html="<script>document.cookie</script>")
        )
        assert feats["has_scripts"] == 1

    def test_attachment_present_flagged(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(attachments=[{"filename": "invoice.exe"}])
        )
        assert feats["has_attachments"] == 1
        assert feats["attachment_count"] == 1

    def test_no_attachment_gives_zero(self, extractor):
        feats, _ = extractor.extract_features(_parsed())
        assert feats["has_attachments"] == 0
        assert feats["attachment_count"] == 0


# ---------------------------------------------------------------------------
# Header mismatch
# ---------------------------------------------------------------------------


class TestHeaderFeatures:
    def test_header_mismatch_detected(self, extractor):
        feats, _ = extractor.extract_features(
            _parsed(header_mismatch=["From domain does not match Reply-To"])
        )
        assert feats["has_reply_to_mismatch"] == 1

    def test_no_mismatch_gives_zero(self, extractor):
        feats, _ = extractor.extract_features(_parsed(header_mismatch=[]))
        assert feats["has_reply_to_mismatch"] == 0
