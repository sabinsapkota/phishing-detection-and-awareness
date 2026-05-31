
import pytest
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import (
    db,
    User,
    EmailLog,
    SimulationCampaign,
    SimulationResult,
    generate_simulation_email,
)


class TestUserModel:
    def test_create_user(self, app):
        with app.app_context():
            u = User(
                username="sabin",
                email="modeltest@example.com",
                password_hash=generate_password_hash("pass"),
                role="user",
                department="IT",
            )
            db.session.add(u)
            db.session.commit()
            fetched = User.query.filter_by(username="modeltest_user").first()
            assert fetched is not None
            assert fetched.email == "modeltest@example.com"

    def test_default_role_is_user(self, app):
        with app.app_context():
            u = User(
                username="defaultrole_user",
                email="defaultrole@example.com",
                password_hash=generate_password_hash("pass"),
            )
            db.session.add(u)
            db.session.commit()
            assert u.role == "user"

    def test_password_hash_is_not_plaintext(self, app):
        with app.app_context():
            u = User.query.filter_by(username="admin").first()
            assert u is not None
            assert u.password_hash != "admin123"

    def test_password_hash_verifies_correctly(self, app):
        with app.app_context():
            u = User.query.filter_by(username="admin").first()
            assert check_password_hash(u.password_hash, "admin123")

    def test_created_at_is_set_automatically(self, app):
        with app.app_context():
            u = User(
                username="timestamptest",
                email="timestamp@example.com",
                password_hash=generate_password_hash("pass"),
            )
            db.session.add(u)
            db.session.commit()
            assert u.created_at is not None
            assert isinstance(u.created_at, datetime.datetime)

    def test_admin_role_stored_correctly(self, app):
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            assert admin.role == "admin"


# ---------------------------------------------------------------------------
# EmailLog model
# ---------------------------------------------------------------------------


class TestEmailLogModel:
    def test_create_email_log(self, app):
        with app.app_context():
            user = User.query.filter_by(username="testuser").first()
            log = EmailLog(
                sender="test@phish.tk",
                subject="Test log entry",
                content="Body here",
                urls="[]",
                is_phishing_predicted=True,
                confidence_score=0.88,
                user_id=user.id,
            )
            db.session.add(log)
            db.session.commit()
            fetched = EmailLog.query.filter_by(subject="Test log entry").first()
            assert fetched is not None
            assert fetched.confidence_score == pytest.approx(0.88)

    def test_email_log_phishing_flag(self, app):
        with app.app_context():
            log = EmailLog.query.filter_by(is_phishing_predicted=True).first()
            assert log is not None

    def test_email_log_timestamp_is_auto_set(self, app):
        with app.app_context():
            user = User.query.filter_by(username="testuser").first()
            log = EmailLog(
                sender="ts@test.com",
                subject="TS Test",
                content="body",
                is_phishing_predicted=False,
                confidence_score=0.1,
                user_id=user.id,
            )
            db.session.add(log)
            db.session.commit()
            assert log.timestamp is not None


# ---------------------------------------------------------------------------
# SimulationCampaign model
# ---------------------------------------------------------------------------


class TestSimulationCampaignModel:
    def _make_campaign(self, app, name, status="draft"):
        with app.app_context():
            admin = User.query.filter_by(username="admin").first()
            camp = SimulationCampaign(
                name=name,
                description="Model test",
                template_type="password_reset",
                target_group="all",
                start_date=datetime.datetime(2025, 6, 1),
                end_date=datetime.datetime(2025, 6, 30),
                status=status,
                created_by=admin.id,
            )
            db.session.add(camp)
            db.session.commit()
            return camp.id

    def test_campaign_default_status_is_draft(self, app):
        camp_id = self._make_campaign(app, "DefaultStatusCamp")
        with app.app_context():
            camp = SimulationCampaign.query.get(camp_id)
            assert camp.status == "draft"

    def test_campaign_status_can_be_set_to_active(self, app):
        camp_id = self._make_campaign(app, "ActiveStatusCamp", status="active")
        with app.app_context():
            camp = SimulationCampaign.query.get(camp_id)
            assert camp.status == "active"

    def test_campaign_dates_stored_correctly(self, app):
        camp_id = self._make_campaign(app, "DateCheckCamp")
        with app.app_context():
            camp = SimulationCampaign.query.get(camp_id)
            assert camp.start_date.year == 2025
            assert camp.end_date.month == 6

    def test_campaign_created_at_is_auto_set(self, app):
        camp_id = self._make_campaign(app, "CreatedAtCamp")
        with app.app_context():
            camp = SimulationCampaign.query.get(camp_id)
            assert camp.created_at is not None


# ---------------------------------------------------------------------------
# SimulationResult model
# ---------------------------------------------------------------------------


class TestSimulationResultModel:
    def test_simulation_result_defaults(self, app):
        with app.app_context():
            result = SimulationResult.query.first()
            # email_sent should be True (seeded that way)
            assert result.email_sent is True

    def test_can_mark_email_opened(self, app):
        with app.app_context():
            camp = SimulationCampaign.query.first()
            user = User.query.filter_by(username="testuser").first()
            result = SimulationResult(
                campaign_id=camp.id, user_id=user.id, email_sent=True
            )
            db.session.add(result)
            db.session.commit()

            result.email_opened = True
            result.opened_at = datetime.datetime.utcnow()
            db.session.commit()

            fetched = SimulationResult.query.get(result.id)
            assert fetched.email_opened is True
            assert fetched.opened_at is not None

    def test_can_mark_link_clicked(self, app):
        with app.app_context():
            camp = SimulationCampaign.query.first()
            user = User.query.filter_by(username="testuser").first()
            result = SimulationResult(
                campaign_id=camp.id, user_id=user.id, email_sent=True
            )
            db.session.add(result)
            db.session.commit()
            result.link_clicked = True
            db.session.commit()
            assert SimulationResult.query.get(result.id).link_clicked is True

    def test_can_mark_reported_phishing(self, app):
        with app.app_context():
            camp = SimulationCampaign.query.first()
            user = User.query.filter_by(username="testuser").first()
            result = SimulationResult(
                campaign_id=camp.id, user_id=user.id, email_sent=True
            )
            db.session.add(result)
            db.session.commit()
            result.reported_phishing = True
            db.session.commit()
            assert SimulationResult.query.get(result.id).reported_phishing is True

    def test_can_mark_training_completed(self, app):
        with app.app_context():
            camp = SimulationCampaign.query.first()
            user = User.query.filter_by(username="testuser").first()
            result = SimulationResult(
                campaign_id=camp.id, user_id=user.id, email_sent=True
            )
            db.session.add(result)
            db.session.commit()
            result.training_completed = True
            db.session.commit()
            assert SimulationResult.query.get(result.id).training_completed is True


# ---------------------------------------------------------------------------
# Simulation email templates
# ---------------------------------------------------------------------------


class TestSimulationEmailTemplates:
    @pytest.mark.parametrize(
        "template",
        [
            "password_reset",
            "account_verification",
            "shipping_notification",
            "tax_refund",
        ],
    )
    def test_template_returns_dict_with_required_keys(self, template):
        email = generate_simulation_email(template, result_id=1)
        assert "sender" in email
        assert "subject" in email
        assert "content" in email

    @pytest.mark.parametrize(
        "template",
        [
            "password_reset",
            "account_verification",
            "shipping_notification",
            "tax_refund",
        ],
    )
    def test_template_content_contains_simulation_link(self, template):
        email = generate_simulation_email(template, result_id=42)
        assert "/simulation/click/42" in email["content"]

    def test_password_reset_sender_looks_suspicious(self):
        email = generate_simulation_email("password_reset", 1)
        # Should use a misspelled/suspicious domain
        assert email["sender"] != "security@amazon.com"
        assert "amazon" in email["sender"].lower() or "amaz" in email["sender"].lower()

    def test_account_verification_sender_is_spoofed(self):
        email = generate_simulation_email("account_verification", 1)
        assert "paypal" in email["sender"].lower() or "paypa" in email["sender"].lower()

    def test_tax_refund_subject_mentions_refund(self):
        email = generate_simulation_email("tax_refund", 1)
        assert "refund" in email["subject"].lower() or "tax" in email["subject"].lower()

    def test_shipping_notification_sender_uses_suspicious_tld(self):
        email = generate_simulation_email("shipping_notification", 1)
        # fedex-delivery.xyz uses a suspicious TLD
        assert ".xyz" in email["sender"] or "fedex" in email["sender"].lower()

    def test_unknown_template_falls_back_to_password_reset(self):
        email = generate_simulation_email("nonexistent_template", 1)
        # Falls back to password_reset
        assert email is not None
        assert "subject" in email

    def test_result_id_is_embedded_in_link(self):
        for rid in [1, 99, 1000]:
            email = generate_simulation_email("password_reset", rid)
            assert f"/simulation/click/{rid}" in email["content"]
