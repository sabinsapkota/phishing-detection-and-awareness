from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pickle
import numpy as np
import re
from urllib.parse import urlparse
import datetime
import random
import string
import json
import os

# Import our custom email parser
from email_parser import FullEmailParser
from email_parser import FullEmailParser, EnhancedFeatureExtractor
import pandas as pd
import pickle
from pathlib import Path

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "your-secret-key-here-change-in-production"
)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///phishing.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Initialize email parser
# At the top of your app file alongside your other globals
model = None
feature_names = []
model_data = {}
parser = FullEmailParser()
extractor = EnhancedFeatureExtractor()


def load_phishing_model():
    """Load the trained ML model (call this in your app factory or before first request)"""
    global model, feature_names, model_data

    model_path = Path("models/phishing_model_enhanced.pkl")

    if not model_path.exists():
        print("⚠️ Warning: Trained model not found! Please train it first.")
        return False

    try:
        with open(model_path, "rb") as f:
            model_data = pickle.load(f)

        model = model_data["model"]
        feature_names = model_data.get("feature_names", [])
        print(f"✅ Trained phishing model loaded successfully")
        print(
            f"   Prediction threshold : {model_data.get('prediction_threshold', 0.65)}"
        )
        print(f"   Features             : {len(feature_names)}")
        print(
            f"   Training accuracy    : {model_data.get('training_info', {}).get('accuracy', 'N/A')}"
        )
        return True
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return False


# Database Models (same as before)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    department = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    simulation_results = db.relationship("SimulationResult", backref="user", lazy=True)


class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    urls = db.Column(db.Text)
    is_phishing_predicted = db.Column(db.Boolean)
    confidence_score = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    full_headers = db.Column(db.Text)  # Store full email headers


class SimulationCampaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    template_type = db.Column(db.String(50))
    target_group = db.Column(db.String(50))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="draft")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class SimulationResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("simulation_campaign.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    email_sent = db.Column(db.Boolean, default=False)
    email_opened = db.Column(db.Boolean, default=False)
    link_clicked = db.Column(db.Boolean, default=False)
    data_entered = db.Column(db.Boolean, default=False)
    reported_phishing = db.Column(db.Boolean, default=False)
    opened_at = db.Column(db.DateTime)
    clicked_at = db.Column(db.DateTime)
    training_completed = db.Column(db.Boolean, default=False)


# Enhanced Feature Extraction
extractor = EnhancedFeatureExtractor()


# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or user.role != "admin":
            flash("Admin access required", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        department = request.form.get("department", "")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return render_template("register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "error")
            return render_template("register.html")

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            department=department,
            role="user",
        )
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    if user.role == "admin":
        stats = get_admin_stats()
        return render_template("admin_dashboard.html", stats=stats)
    else:
        simulations = SimulationResult.query.filter_by(user_id=user.id).all()
        training_completed = SimulationResult.query.filter_by(
            user_id=user.id, training_completed=True
        ).count()
        print(
            f"User {user.username} has completed training for {training_completed} simulations."
        )
        return render_template(
            "user_dashboard.html",
            simulations=simulations,
            training_completed=training_completed,
        )


@app.route("/detect", methods=["GET", "POST"])
@login_required
def detect():

    threshold = model_data.get("prediction_threshold", 0.65)

    if request.method == "POST":

        input_type = request.form.get("input_type", "simple")

        # =====================================================
        # FULL EMAIL MODE
        # =====================================================
        if input_type == "full":

            full_email = request.form.get("full_email", "")

            if not full_email.strip():
                flash("Please paste the complete email", "error")
                return render_template("detect.html")

            parsed = parser.parse_full_email(full_email)
            features_dict = extractor.extract_features(parsed)

        # =====================================================
        # SIMPLE MODE
        # =====================================================
        else:

            sender = request.form.get("sender", "")
            subject = request.form.get("subject", "")
            content = request.form.get("content", "")

            # Build a minimal, realistic email text
            simple_email = f"""From: {sender}
            Subject: {subject}

            {content}"""

            # Now use the same parser as full mode
            parsed = parser.parse_full_email(simple_email)
            features_dict = extractor.extract_features(parsed)

        # =====================================================
        # FEATURE ALIGNMENT (FIXED)
        # =====================================================
        features_df = pd.DataFrame([features_dict])

        if feature_names:
            features_df = features_df.reindex(columns=feature_names, fill_value=0)

        # =====================================================
        # MODEL PREDICTION (FIXED CONSISTENCY)
        # =====================================================
        if model is None:
            confidence = 0.0
            is_phishing = False
        else:
            probability = model.predict_proba(features_df)[0][1]
            confidence = float(probability)

            is_phishing = confidence >= threshold

        # =====================================================
        # RISK LEVEL (CONSISTENT WITH THRESHOLD)
        # =====================================================
        if confidence >= threshold:
            risk_level = "HIGH"
        elif confidence >= threshold * 0.8:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # =====================================================
        # RESPONSE
        # =====================================================
        result = {
            "is_phishing": is_phishing,
            "confidence": round(confidence * 100, 2),
            "risk_level": risk_level,
            "features": features_dict,
            "urls_found": parsed.get("urls", []),
            "reasoning": get_ml_reasoning(
                features_dict, is_phishing, confidence, threshold
            ),
        }

        # =====================================================
        # SAFE USER ID HANDLING (FIXED)
        # =====================================================
        email_log = EmailLog(
            sender=parsed.get("from", "unknown"),
            subject=parsed.get("subject", "No Subject"),
            content=parsed.get("body_plain", "")[:2000],
            urls=json.dumps(parsed.get("urls", [])),
            is_phishing_predicted=is_phishing,
            confidence_score=confidence,
            user_id=session.get("user_id", None),
            full_headers=(
                json.dumps(parsed.get("headers", {}))
                if isinstance(parsed.get("headers"), dict)
                else "{}"
            ),
        )

        db.session.add(email_log)
        db.session.commit()

        email_data = {
            "input_type": input_type,
            "parsed": parsed if input_type == "full" else None,
            "sender": parsed.get("from"),
            "subject": parsed.get("subject"),
            "content": parsed.get("body_plain", parsed.get("body_combined", "")),
        }

        return render_template("detection_result.html", result=result, email=email_data)

    return render_template("detect.html")


# =========================================================
# FIXED REASONING ENGINE
# =========================================================
def get_ml_reasoning(features, is_phishing, confidence, threshold):

    reasons = []

    if not isinstance(features, dict):
        features = {}

    # =====================================================
    # ONLY EXPLAIN IF MODEL TRIGGERS PHISHING
    # =====================================================
    if confidence >= threshold:

        if features.get("num_urls", 0) > 2:
            reasons.append("Multiple links detected in email")

        if features.get("suspicious_url_score", 0) > 0:
            reasons.append("Suspicious URL patterns found")

        if features.get("credential_intent", 0) == 1:
            reasons.append("Email requests sensitive credentials")

        if features.get("urgent_score", 0) > 2:
            reasons.append("High urgency pressure language detected")

        if features.get("has_ip_in_url", 0) == 1:
            reasons.append("URL contains raw IP address (high risk)")

        if features.get("header_mismatch", 0) == 1:
            reasons.append("Email header inconsistency detected")

        if features.get("return_path_domain_mismatch", 0) == 1:
            reasons.append("Return-Path mismatch (possible spoofing)")

        if features.get("reply_to_domain_mismatch", 0) == 1:
            reasons.append("Reply-To mismatch detected")

        if features.get("suspicious_multi_domain_count", 0) > 0:
            reasons.append("Multiple unrelated domains detected")

        if features.get("exclamation_count", 0) > 5:
            reasons.append("Excessive use of exclamation marks")

        if features.get("capital_ratio", 0) > 0.25:
            reasons.append("Unusual capital letter usage")

    # =====================================================
    # SAFE / LEGITIMATE EMAIL EXPLANATION
    # =====================================================
    else:

        if features.get("institutional_score", 0) > 2:
            reasons.append("Institutional/academic communication detected")

        if features.get("institutional_override", 0) == 1:
            reasons.append("Low risk: institutional email with no credential request")

        if features.get("is_edu_domain", 0) == 1:
            reasons.append("Trusted educational domain detected")

        if features.get("is_trusted_org", 0) == 1:
            reasons.append("Trusted organization domain detected")

        reasons.append("No strong phishing indicators detected")

    return reasons


# =========================================================
# API ENDPOINT (FIXED CONSISTENCY)
# =========================================================
@app.route("/api/detect", methods=["POST"])
@login_required
def api_detect():

    data = request.get_json()
    email_text = data.get("email", "")

    if not email_text:
        return jsonify({"error": "No email content provided"}), 400

    threshold = model_data.get("prediction_threshold", 0.65)

    parsed = parser.parse_full_email(email_text)
    features_dict = extractor.extract_features(parsed)

    features_df = pd.DataFrame([features_dict])

    if feature_names:
        features_df = features_df.reindex(columns=feature_names, fill_value=0)

    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    probability = model.predict_proba(features_df)[0][1]
    confidence = float(probability)

    is_phishing = confidence >= threshold

    if confidence >= threshold:
        risk_level = "HIGH"
    elif confidence >= threshold * 0.8:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    result = {
        "is_phishing": is_phishing,
        "confidence": round(confidence * 100, 2),
        "risk_level": risk_level,
        "indicators": get_ml_reasoning(
            features_dict, is_phishing, confidence, threshold
        ),
        "urls_found": parsed.get("urls", []),
        "features": features_dict,
    }

    email_log = EmailLog(
        sender=parsed.get("from", "API"),
        subject=parsed.get("subject", "API Detection"),
        content=parsed.get("body_plain", "")[:1000],
        urls=json.dumps(parsed.get("urls", [])),
        is_phishing_predicted=is_phishing,
        confidence_score=confidence,
        user_id=session.get("user_id", None),
    )

    db.session.add(email_log)
    db.session.commit()

    return jsonify(result)


# Admin routes (simplified)
@app.route("/admin/campaigns")
@admin_required
def campaigns():
    campaigns = SimulationCampaign.query.all()
    return render_template("campaigns.html", campaigns=campaigns)


@app.route("/admin/campaign/create", methods=["GET", "POST"])
@admin_required
def create_campaign():
    if request.method == "POST":
        campaign = SimulationCampaign(
            name=request.form["name"],
            description=request.form["description"],
            template_type=request.form["template_type"],
            target_group=request.form["target_group"],
            start_date=datetime.datetime.strptime(
                request.form["start_date"], "%Y-%m-%d"
            ),
            end_date=datetime.datetime.strptime(request.form["end_date"], "%Y-%m-%d"),
            status="draft",
            created_by=session["user_id"],
        )
        db.session.add(campaign)
        db.session.commit()
        flash("Campaign created successfully", "success")
        return redirect(url_for("campaigns"))

    templates = [
        "password_reset",
        "account_verification",
        "shipping_notification",
        "tax_refund",
    ]
    departments = db.session.query(User.department).distinct().all()
    return render_template(
        "create_campaign.html",
        templates=templates,
        departments=[d[0] for d in departments if d[0]],
    )


@app.route("/admin/campaign/launch/<int:campaign_id>")
@admin_required
def launch_campaign(campaign_id):
    campaign = SimulationCampaign.query.get_or_404(campaign_id)

    if campaign.target_group == "all":
        users = User.query.filter_by(role="user").all()
    else:
        users = User.query.filter_by(department=campaign.target_group).all()

    for user in users:
        result = SimulationResult(
            campaign_id=campaign.id, user_id=user.id, email_sent=True
        )
        db.session.add(result)

    campaign.status = "active"
    db.session.commit()
    flash(f"Campaign launched to {len(users)} users", "success")
    return redirect(url_for("campaigns"))


@app.route("/admin/analytics")
@admin_required
def analytics():
    total_emails = EmailLog.query.count()
    phishing_detected = EmailLog.query.filter_by(is_phishing_predicted=True).count()
    total_campaigns = SimulationCampaign.query.count()
    active_campaigns = SimulationCampaign.query.filter_by(status="active").count()

    total_simulations = SimulationResult.query.count()
    clicked_count = SimulationResult.query.filter_by(link_clicked=True).count()
    reported_count = SimulationResult.query.filter_by(reported_phishing=True).count()

    click_rate = (
        (clicked_count / total_simulations * 100) if total_simulations > 0 else 0
    )
    report_rate = (
        (reported_count / total_simulations * 100) if total_simulations > 0 else 0
    )
    users_trained = SimulationResult.query.filter_by(training_completed=True).count()

    return render_template(
        "analytics.html",
        stats={
            "total_emails": total_emails,
            "phishing_detected": phishing_detected,
            "detection_rate": (
                round(phishing_detected / total_emails * 100, 2) if total_emails else 0
            ),
            "total_campaigns": total_campaigns,
            "active_campaigns": active_campaigns,
            "click_rate": round(click_rate, 2),
            "report_rate": round(report_rate, 2),
            "improvement_score": round(report_rate - click_rate + 50, 2),
            "users_trained": users_trained,
        },
    )


# Simulation routes
@app.route("/simulation/email/<int:result_id>")
@login_required
def view_simulation_email(result_id):
    result = SimulationResult.query.get_or_404(result_id)

    if result.user_id != session["user_id"] and session.get("role") != "admin":
        flash("Unauthorized access", "error")
        return redirect(url_for("dashboard"))

    if not result.email_opened:
        result.email_opened = True
        result.opened_at = datetime.datetime.utcnow()
        db.session.commit()

    campaign = SimulationCampaign.query.get(result.campaign_id)
    email_content = generate_simulation_email(campaign.template_type, result_id)

    return render_template(
        "simulation_email.html", email=email_content, result_id=result_id
    )


@app.route("/simulation/click/<int:result_id>")
@login_required
def simulation_click(result_id):
    result = SimulationResult.query.get_or_404(result_id)

    if result.user_id != session["user_id"]:
        return redirect(url_for("dashboard"))

    result.link_clicked = True
    result.clicked_at = datetime.datetime.utcnow()
    db.session.commit()

    return render_template(
        "simulation_landing.html", result_id=result_id, campaign_id=result.campaign_id
    )


@app.route("/simulation/report/<int:result_id>")
@login_required
def report_simulation(result_id):
    result = SimulationResult.query.get_or_404(result_id)

    if result.user_id != session["user_id"]:
        return redirect(url_for("dashboard"))

    result.reported_phishing = True
    db.session.commit()

    flash("Excellent! You correctly identified this as a phishing attempt.", "success")
    return redirect(url_for("dashboard"))


# @app.route("/simulation/training/<int:result_id>", methods=["POST"])
# @login_required
# def complete_training(result_id):
#     result = SimulationResult.query.get_or_404(result_id)

#     if result.user_id != session["user_id"]:
#         return redirect(url_for("dashboard"))

#     score = request.form.get("score", 0, type=int)

#     if score >= 17:
#         result.training_completed = True
#         db.session.commit()
#         flash("Training completed. Remember these warning signs for future emails!", "info")
#     else:
#         flash(f"Score of {score}/20 is below the required 17. Please retake the quiz to complete training.", "warning")


#     return redirect(url_for("dashboard"))
@app.route("/simulation/training/complete", methods=["POST"])
@login_required
def complete_training():
    score = request.form.get("score", 0, type=int)
    print(f"Received training score: {score}")
    if score >= 17:
        result = (
            SimulationResult.query.filter_by(user_id=session["user_id"])
            .order_by(SimulationResult.id.desc())
            .first()
        )

        if result:
            result.training_completed = True
            result.user_id = session["user_id"]

            db.session.commit()
            flash("Training completed!", "info")
        else:
            flash("No simulation result found.", "warning")

    else:
        flash(f"Score {score}/20 is below 17. Please retake the quiz.", "warning")

    return redirect(url_for("dashboard"))


def generate_simulation_email(template_type, result_id):
    templates = {
        "password_reset": {
            "sender": "security@amaz0n-security.com",
            "subject": "Urgent: Password Reset Required",
            "content": f"""<p>Dear User,</p>
            <p>We detected unusual activity on your account. Your password must be reset immediately to prevent suspension.</p>
            <p><a href="/simulation/click/{result_id}" style="background: #ff9900; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password Now</a></p>
            <p>If you do not reset within 24 hours, your account will be permanently locked.</p>
            <p>Best regards,<br>Security Team</p>""",
        },
        "account_verification": {
            "sender": "verify@paypa1-verify.net",
            "subject": "Action Required: Verify Your Account",
            "content": f"""<p>Hello,</p>
            <p>Your account access has been limited. Please verify your information to restore full access.</p>
            <p><a href="/simulation/click/{result_id}" style="background: #0070ba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Account</a></p>
            <p>Failure to verify may result in account closure.</p>""",
        },
        "shipping_notification": {
            "sender": "shipping@fedex-delivery.xyz",
            "subject": "Package Delivery Failed - Action Needed",
            "content": f"""<p>Dear Customer,</p>
            <p>We attempted to deliver your package but no one was available. Please reschedule delivery.</p>
            <p><a href="/simulation/click/{result_id}" style="background: #4d148c; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reschedule Delivery</a></p>
            <p>Package will be returned to sender in 48 hours if not rescheduled.</p>""",
        },
        "tax_refund": {
            "sender": "refunds@irs-gov-refund.com",
            "subject": "You Have a Tax Refund Pending",
            "content": f"""<p>Dear Taxpayer,</p>
            <p>Good news! You are eligible for an additional tax refund of $847.29.</p>
            <p><a href="/simulation/click/{result_id}" style="background: #2e7d32; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Claim Refund</a></p>
            <p>Claim must be submitted within 7 days.</p>""",
        },
    }

    template = templates.get(template_type, templates["password_reset"])
    return {
        "sender": template["sender"],
        "subject": template["subject"],
        "content": template["content"],
    }


def get_admin_stats():
    """Get statistics for admin dashboard"""
    return {
        "total_users": User.query.filter_by(role="user").count(),
        "total_emails_scanned": EmailLog.query.count(),
        "phishing_detected": EmailLog.query.filter_by(
            is_phishing_predicted=True
        ).count(),
        "active_campaigns": SimulationCampaign.query.filter_by(status="active").count(),
        "total_simulations": SimulationResult.query.count(),
        "users_trained": SimulationResult.query.filter_by(
            training_completed=True
        ).count(),
    }


@app.route("/training")
@login_required
def training():
    return render_template("training.html")


@app.route("/api/stats")
@admin_required
def api_stats():
    stats = get_admin_stats()
    return jsonify(stats)


if __name__ == "__main__":
    load_phishing_model()
    with app.app_context():
        db.create_all()

        # Create default admin user if not exists
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@phishingtool.com",
                password_hash=generate_password_hash("admin123"),
                role="admin",
                department="IT Security",
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin created: username='admin', password='admin123'")

    app.run(debug=True, host="0.0.0.0", port=5000)
