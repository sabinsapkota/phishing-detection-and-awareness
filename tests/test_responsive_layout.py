

import pytest
import re


def _html(resp):
    return resp.data.decode("utf-8", errors="replace")


RESPONSIVE_CHECKS = [
    # (description, substring or regex to find)
    ("Bootstrap viewport meta", 'name="viewport"'),
    ("Bootstrap CSS link", "bootstrap"),
    ("Font Awesome CSS", "font-awesome"),
    ("Navbar toggler (hamburger)", "navbar-toggler"),
    ("Bootstrap container", 'class="container"'),
    ("Footer element", "<footer"),
]


def _assert_responsive(resp):
    html = _html(resp)
    for desc, token in RESPONSIVE_CHECKS:
        assert token in html, f"Missing responsive element: {desc!r} ({token!r})"




class TestPublicPagesLayout:
    def test_home_page_is_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type

    def test_home_page_is_responsive(self, client):
        _assert_responsive(client.get("/"))

    def test_home_page_has_title(self, client):
        html = _html(client.get("/"))
        assert "<title>" in html and "</title>" in html
        title_match = re.search(r"<title>(.*?)</title>", html, re.DOTALL)
        assert title_match and title_match.group(1).strip()

    def test_home_page_has_cta_buttons(self, client):
        html = _html(client.get("/"))
        assert "Get Started" in html or "Login" in html

    def test_login_page_is_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_login_page_is_responsive(self, client):
        _assert_responsive(client.get("/login"))

    def test_login_page_title(self, client):
        html = _html(client.get("/login"))
        assert "Login" in html or "PhishGuard" in html

    def test_login_page_has_form_fields(self, client):
        html = _html(client.get("/login"))
        assert 'name="username"' in html
        assert 'name="password"' in html

    def test_register_page_is_200(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200

    def test_register_page_is_responsive(self, client):
        _assert_responsive(client.get("/register"))

    def test_register_page_has_department_select(self, client):
        html = _html(client.get("/register"))
        assert 'name="department"' in html

    def test_register_page_has_email_field(self, client):
        html = _html(client.get("/register"))
        assert 'type="email"' in html


# ---------------------------------------------------------------------------
# Authenticated user pages
# ---------------------------------------------------------------------------


class TestUserPagesLayout:
    def test_user_dashboard_is_200(self, user_client):
        resp = user_client.get("/dashboard")
        assert resp.status_code == 200

    def test_user_dashboard_is_responsive(self, user_client):
        _assert_responsive(user_client.get("/dashboard"))

    def test_user_dashboard_shows_simulation_table_or_empty(self, user_client):
        html = _html(user_client.get("/dashboard"))
        assert "Simulation" in html or "simulation" in html

    def test_user_dashboard_has_quick_actions(self, user_client):
        html = _html(user_client.get("/dashboard"))
        assert "Analyze Email" in html or "Training" in html

    def test_user_dashboard_has_progress_bars(self, user_client):
        html = _html(user_client.get("/dashboard"))
        assert "progress" in html

    def test_detect_page_is_200(self, user_client):
        resp = user_client.get("/detect")
        assert resp.status_code == 200

    def test_detect_page_is_responsive(self, user_client):
        _assert_responsive(user_client.get("/detect"))

    def test_detect_page_has_two_tabs(self, user_client):
        html = _html(user_client.get("/detect"))
        assert "Full Email" in html and "Simple" in html

    def test_detect_page_has_submit_button(self, user_client):
        html = _html(user_client.get("/detect"))
        assert "Analyze" in html

    def test_training_page_is_200(self, user_client):
        resp = user_client.get("/training")
        assert resp.status_code == 200

    def test_training_page_is_responsive(self, user_client):
        _assert_responsive(user_client.get("/training"))


# ---------------------------------------------------------------------------
# Admin pages
# ---------------------------------------------------------------------------


class TestAdminPagesLayout:
    def test_admin_dashboard_is_200(self, admin_client):
        resp = admin_client.get("/dashboard")
        assert resp.status_code == 200

    def test_admin_dashboard_is_responsive(self, admin_client):
        _assert_responsive(admin_client.get("/dashboard"))

    def test_admin_dashboard_shows_stat_cards(self, admin_client):
        html = _html(admin_client.get("/dashboard"))
        assert "Total Users" in html
        assert "Emails Scanned" in html

    def test_admin_dashboard_shows_system_status(self, admin_client):
        html = _html(admin_client.get("/dashboard"))
        assert "System Status" in html or "Operational" in html

    def test_admin_dashboard_has_admin_badge(self, admin_client):
        html = _html(admin_client.get("/dashboard"))
        assert "Administrator" in html

    def test_campaigns_page_is_200(self, admin_client):
        resp = admin_client.get("/admin/campaigns")
        assert resp.status_code == 200

    def test_campaigns_page_is_responsive(self, admin_client):
        _assert_responsive(admin_client.get("/admin/campaigns"))

    def test_campaigns_page_has_create_button(self, admin_client):
        html = _html(admin_client.get("/admin/campaigns"))
        assert "Create Campaign" in html or "Create" in html

    def test_create_campaign_page_is_200(self, admin_client):
        resp = admin_client.get("/admin/campaign/create")
        assert resp.status_code == 200

    def test_create_campaign_page_is_responsive(self, admin_client):
        _assert_responsive(admin_client.get("/admin/campaign/create"))

    def test_analytics_page_is_200(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        assert resp.status_code == 200

    def test_analytics_page_is_responsive(self, admin_client):
        _assert_responsive(admin_client.get("/admin/analytics"))

    def test_analytics_page_has_canvas_charts(self, admin_client):
        html = _html(admin_client.get("/admin/analytics"))
        assert "<canvas" in html


# ---------------------------------------------------------------------------
# Navbar content by role
# ---------------------------------------------------------------------------


class TestNavbarByRole:
    def test_unauthenticated_navbar_shows_login_and_register(self, client):
        html = _html(client.get("/"))
        assert "Login" in html
        assert "Register" in html

    def test_user_navbar_shows_dashboard_and_detect(self, user_client):
        html = _html(user_client.get("/dashboard"))
        assert "Dashboard" in html
        assert "Detect" in html

    def test_user_navbar_does_not_show_admin_menu(self, user_client):
        html = _html(user_client.get("/dashboard"))
        # The admin dropdown only appears when role == 'admin'
        assert 'id="adminDropdown"' not in html

    def test_admin_navbar_shows_admin_dropdown(self, admin_client):
        html = _html(admin_client.get("/dashboard"))
        assert "adminDropdown" in html or "Admin" in html

    def test_navbar_shows_logout_with_username_when_logged_in(self, user_client):
        html = _html(user_client.get("/dashboard"))
        assert "testuser" in html
        assert "Logout" in html

    def test_navbar_brand_is_phishguard(self, client):
        html = _html(client.get("/"))
        assert "PhishGuard" in html


# ---------------------------------------------------------------------------
# Page title correctness
# ---------------------------------------------------------------------------


class TestPageTitles:
    @pytest.mark.parametrize(
        "url,expected_fragment",
        [
            ("/", "PhishGuard"),
            ("/login", "Login"),
            ("/register", "Register"),
        ],
    )
    def test_public_page_titles(self, client, url, expected_fragment):
        html = _html(client.get(url))
        title_match = re.search(r"<title>(.*?)</title>", html, re.DOTALL)
        assert title_match, f"No <title> on {url}"
        assert expected_fragment in title_match.group(1)

    @pytest.mark.parametrize(
        "url,expected_fragment",
        [
            ("/dashboard", "Dashboard"),
            ("/detect", "Detection"),
            ("/training", "Training"),
        ],
    )
    def test_user_page_titles(self, user_client, url, expected_fragment):
        html = _html(user_client.get(url))
        title_match = re.search(r"<title>(.*?)</title>", html, re.DOTALL)
        assert title_match, f"No <title> on {url}"
        assert expected_fragment in title_match.group(1)

    @pytest.mark.parametrize(
        "url,expected_fragment",
        [
            ("/admin/campaigns", "Campaign"),
            ("/admin/campaign/create", "Campaign"),
            ("/admin/analytics", "Analytics"),
        ],
    )
    def test_admin_page_titles(self, admin_client, url, expected_fragment):
        html = _html(admin_client.get(url))
        title_match = re.search(r"<title>(.*?)</title>", html, re.DOTALL)
        assert title_match, f"No <title> on {url}"
        assert expected_fragment in title_match.group(1)
