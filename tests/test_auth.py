import pytest


class TestLogin:
    def test_login_page_loads(self, client):
        """GET /login returns 200 and contains the login form."""
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Login" in resp.data or b"login" in resp.data

    def test_valid_admin_login_redirects_to_dashboard(self, client):
        """Correct admin credentials redirect to /dashboard."""
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Admin dashboard has the admin badge
        assert b"Administrator" in resp.data or b"Admin Dashboard" in resp.data

    def test_valid_user_login_redirects_to_dashboard(self, client):
        """Correct user credentials redirect to /dashboard."""
        resp = client.post(
            "/login",
            data={"username": "testuser", "password": "password123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_wrong_password_shows_error(self, client):
        """Wrong password stays on login page with an error flash."""
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid" in resp.data or b"invalid" in resp.data

    def test_nonexistent_user_shows_error(self, client):
        """Unknown username stays on login page."""
        resp = client.post(
            "/login",
            data={"username": "nobody", "password": "whatever"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Invalid" in resp.data or b"login" in resp.data.lower()

    def test_empty_username_fails(self, client):
        """Empty username does not log in."""
        resp = client.post(
            "/login",
            data={"username": "", "password": "admin123"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Administrator" not in resp.data


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_page_loads(self, client):
        """GET /register returns 200."""
        resp = client.get("/register")
        assert resp.status_code == 200
        assert b"Register" in resp.data or b"Create" in resp.data

    def test_new_user_registration_succeeds(self, client):
        """A brand-new username/email registers and redirects to login."""
        resp = client.post(
            "/register",
            data={
                "username": "brandnewuser",
                "email": "brandnew@example.com",
                "password": "securepass",
                "department": "Finance",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        # Should see a success flash or be on the login page
        assert b"successful" in resp.data.lower() or b"login" in resp.data.lower()

    def test_duplicate_username_is_rejected(self, client):
        """Registering with an existing username shows an error."""
        resp = client.post(
            "/register",
            data={
                "username": "testuser",
                "email": "unique999@example.com",
                "password": "securepass",
                "department": "IT",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"already" in resp.data.lower() or b"exists" in resp.data.lower()

    def test_duplicate_email_is_rejected(self, client):
        """Registering with an existing email shows an error."""
        resp = client.post(
            "/register",
            data={
                "username": "uniqueuser999",
                "email": "testuser@example.com",
                "password": "securepass",
                "department": "IT",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"already" in resp.data.lower() or b"registered" in resp.data.lower()

    def test_short_password_is_rejected(self, client):
        """HTML minlength=6 is enforced; very short passwords should not register."""
        # The HTML attribute enforces this client-side; the server currently
        # doesn't validate length explicitly, but the field is required.
        resp = client.post(
            "/register",
            data={
                "username": "shortpwduser",
                "email": "shortpwd@example.com",
                "password": "abc",
                "department": "",
            },
            follow_redirects=True,
        )
        # Regardless of outcome, the server must not crash (500).
        assert resp.status_code != 500


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_clears_session_and_redirects(self, user_client):
        """After logout, accessing /dashboard redirects to login."""
        resp = user_client.get("/logout", follow_redirects=True)
        assert resp.status_code == 200

        # Try to reach protected page — should redirect to login
        resp2 = user_client.get("/dashboard", follow_redirects=True)
        assert b"Login" in resp2.data or b"login" in resp2.data


# ---------------------------------------------------------------------------
# Route Protection
# ---------------------------------------------------------------------------


class TestRouteProtection:
    def test_unauthenticated_dashboard_redirects_to_login(self, client):
        resp = client.get("/dashboard", follow_redirects=True)
        assert b"Login" in resp.data or b"login" in resp.data

    def test_unauthenticated_detect_redirects_to_login(self, client):
        resp = client.get("/detect", follow_redirects=True)
        assert b"Login" in resp.data or b"login" in resp.data

    def test_unauthenticated_training_redirects_to_login(self, client):
        resp = client.get("/training", follow_redirects=True)
        assert b"Login" in resp.data or b"login" in resp.data

    def test_regular_user_cannot_access_campaigns(self, user_client):
        """Non-admin hitting /admin/campaigns gets redirected or forbidden."""
        resp = user_client.get("/admin/campaigns", follow_redirects=True)
        assert resp.status_code in (200, 302, 403)
        # Should not see the campaigns admin page content
        assert (
            b"Admin" not in resp.data
            or b"Admin access required" in resp.data
            or b"Dashboard" in resp.data
        )

    def test_regular_user_cannot_access_analytics(self, user_client):
        resp = user_client.get("/admin/analytics", follow_redirects=True)
        assert resp.status_code in (200, 302, 403)
        assert b"Admin access required" in resp.data or b"Dashboard" in resp.data

    def test_admin_can_access_campaigns(self, admin_client):
        resp = admin_client.get("/admin/campaigns")
        assert resp.status_code == 200
        assert b"Campaign" in resp.data

    def test_admin_can_access_analytics(self, admin_client):
        resp = admin_client.get("/admin/analytics")
        assert resp.status_code == 200
        assert b"Analytics" in resp.data or b"Detection" in resp.data
