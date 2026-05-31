"""
conftest.py — shared pytest fixtures for PhishGuard test suite.

All tests import from here automatically via pytest discovery.
"""

import pytest
import sys
import os

# ---------------------------------------------------------------------------
# Make the project root importable without installing the package
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Minimal stubs for modules that are not available in the test environment
# (email_parser, trained model, pandas).  These keep the import chain alive
# so we can test everything else.
# ---------------------------------------------------------------------------
from unittest.mock import MagicMock, patch

# Stub email_parser
email_parser_stub = MagicMock()


class _FakeParser:
    def parse_full_email(self, text):
        lines = text.splitlines()
        subject = next(
            (
                l.split(":", 1)[1].strip()
                for l in lines
                if l.lower().startswith("subject:")
            ),
            "No Subject",
        )
        from_ = next(
            (
                l.split(":", 1)[1].strip()
                for l in lines
                if l.lower().startswith("from:")
            ),
            "unknown@example.com",
        )
        body = "\n".join(
            lines[
                next((i for i, l in enumerate(lines) if l.strip() == ""), len(lines))
                + 1 :
            ]
        )
        return {
            "from": from_,
            "subject": subject,
            "body_plain": body,
            "body_html": "",
            "urls": [],
            "attachments": [],
            "header_mismatch": [],
            "headers": {},
        }


class _FakeExtractor:
    def extract_features(self, parsed):
        text = (parsed.get("body_plain", "") + " " + parsed.get("subject", "")).lower()
        return {
            "url_count": 0,
            "has_ip_url": 0,
            "has_suspicious_tld": 0,
            "domain_count": 0,
            "has_misspelled_domain": 0,
            "has_urgent_words": int(
                any(w in text for w in ["urgent", "immediate", "alert"])
            ),
            "urgent_word_count": sum(
                1 for w in ["urgent", "immediate", "alert"] if w in text
            ),
            "has_suspicious_words": 0,
            "suspicious_word_count": 0,
            "exclamation_count": text.count("!"),
            "question_count": text.count("?"),
            "dollar_count": text.count("$"),
            "capital_ratio": 0.05,
            "body_length": len(parsed.get("body_plain", "")),
            "subject_length": len(parsed.get("subject", "")),
            "sender_has_numbers": 0,
            "sender_suspicious_tld": 0,
            "sender_disposable": 0,
            "has_reply_to_mismatch": 0,
            "header_mismatch": 0,
            "subject_has_urgent": 0,
            "subject_exclamation": 0,
            "subject_all_caps": 0,
            "has_html": 0,
            "has_forms": 0,
            "has_scripts": 0,
            "has_attachments": 0,
            "attachment_count": 0,
            # extra keys referenced in result rendering
            "num_urls": 0,
            "suspicious_tld_count": 0,
            "has_ip_in_url": 0,
        }


email_parser_stub.FullEmailParser = _FakeParser
email_parser_stub.EnhancedFeatureExtractor = _FakeExtractor
sys.modules["email_parser"] = email_parser_stub

# Stub pandas
pandas_stub = MagicMock()


class _FakeDF:
    def __init__(self, data):
        self._data = data

    def __getitem__(self, item):
        return self

    def __setitem__(self, key, value):
        pass

    @property
    def columns(self):
        return list(self._data[0].keys()) if self._data else []


pandas_stub.DataFrame = lambda data: _FakeDF(data)
sys.modules["pandas"] = pandas_stub
sys.modules["pd"] = pandas_stub

# ---------------------------------------------------------------------------
# Now import the Flask app (model loading is skipped because the .pkl is absent)
# ---------------------------------------------------------------------------
import importlib, types

# Patch pathlib.Path.exists to return False so load_phishing_model() exits early
from pathlib import Path as _Path

_orig_exists = _Path.exists


def _patched_exists(self):
    if "phishing_model" in str(self):
        return False
    return _orig_exists(self)


_Path.exists = _patched_exists

from app import app as flask_app, db

_Path.exists = _orig_exists  # restore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def app():
    flask_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SECRET_KEY="test-secret-key",
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.create_all()
        _seed_db()
    yield flask_app


def _seed_db():
    from app import User, SimulationCampaign, SimulationResult, EmailLog
    from werkzeug.security import generate_password_hash
    import datetime

    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email="admin@phishingtool.com",
            password_hash=generate_password_hash("admin123"),
            role="admin",
            department="IT Security",
        )
        db.session.add(admin)

    if not User.query.filter_by(username="testuser").first():
        user = User(
            username="testuser",
            email="testuser@example.com",
            password_hash=generate_password_hash("password123"),
            role="user",
            department="HR",
        )
        db.session.add(user)

    db.session.commit()

    user = User.query.filter_by(username="testuser").first()
    campaign = SimulationCampaign(
        name="Test Campaign",
        description="Seed campaign for tests",
        template_type="password_reset",
        target_group="HR",
        start_date=datetime.datetime(2025, 1, 1),
        end_date=datetime.datetime(2025, 12, 31),
        status="active",
        created_by=User.query.filter_by(username="admin").first().id,
    )
    db.session.add(campaign)
    db.session.commit()

    sim = SimulationResult(
        campaign_id=campaign.id,
        user_id=user.id,
        email_sent=True,
        email_opened=False,
        link_clicked=False,
        reported_phishing=False,
        training_completed=False,
    )
    db.session.add(sim)

    log = EmailLog(
        sender="phish@evil.tk",
        subject="Urgent: reset now",
        content="Click here immediately",
        urls='["http://evil.tk/reset"]',
        is_phishing_predicted=True,
        confidence_score=0.92,
        user_id=user.id,
    )
    db.session.add(log)
    db.session.commit()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_client(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})
    return client


@pytest.fixture()
def user_client(client):
    client.post("/login", data={"username": "testuser", "password": "password123"})
    return client


@pytest.fixture()
def app_ctx(app):
    with app.app_context():
        yield
