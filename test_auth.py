import os
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("FIRMWAREX_SECRET_KEY", "test-secret-key-with-at-least-32-characters")

from app import add_user, create_app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database = Path(self.temp_dir.name) / "test.sqlite3"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "unit-test-secret-key",
                "DATABASE": str(database),
                "RATELIMIT_ENABLED": False,
            }
        )
        self.client = self.app.test_client()
        with self.app.app_context():
            add_user("analyst", "a-long-test-password-123")

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, response):
        token = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(token)
        return token.group(1).decode()

    def test_dashboard_and_assets_require_authentication(self):
        for path in ("/", "/styles.css", "/app.js"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])

    def test_login_requires_csrf_token(self):
        response = self.client.post(
            "/login", data={"username": "analyst", "password": "a-long-test-password-123"}
        )
        self.assertEqual(response.status_code, 400)

    def test_login_and_csrf_protected_logout(self):
        login_page = self.client.get("/login")
        response = self.client.post(
            "/login",
            data={
                "username": "analyst",
                "password": "a-long-test-password-123",
                "csrf_token": self.csrf_token(login_page),
            },
        )
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"analyst", dashboard.data)

        logout = self.client.post("/logout", data={"csrf_token": self.csrf_token(dashboard)})
        self.assertEqual(logout.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_invalid_credentials_do_not_open_dashboard(self):
        login_page = self.client.get("/login")
        response = self.client.post(
            "/login",
            data={
                "username": "analyst",
                "password": "incorrect-password",
                "csrf_token": self.csrf_token(login_page),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"was not recognized", response.data)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_browser_setup_creates_first_account_and_closes(self):
        setup_database = Path(self.temp_dir.name) / "setup.sqlite3"
        setup_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "unit-test-secret-key",
                "DATABASE": str(setup_database),
                "RATELIMIT_ENABLED": False,
            }
        )
        client = setup_app.test_client()
        login_page = client.get("/login")
        self.assertIn(b"Set up the administrator account", login_page.data)

        setup_page = client.get("/setup")
        csrf_token = self.csrf_token(setup_page)
        password = "correct-horse-battery-88"
        short_password = client.post(
            "/setup",
            data={
                "username": "admin",
                "password": "short",
                "confirm_password": "short",
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(short_password.status_code, 200)
        self.assertIn(b"at least 14 characters", short_password.data)

        mismatch = client.post(
            "/setup",
            data={
                "username": "admin",
                "password": password,
                "confirm_password": "different-password-value",
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(mismatch.status_code, 200)
        self.assertIn(b"passwords do not match", mismatch.data)

        created = client.post(
            "/setup",
            data={
                "username": "admin",
                "password": password,
                "confirm_password": password,
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(created.status_code, 302)
        self.assertEqual(created.headers["Location"], "/login")
        self.assertEqual(client.get("/setup").headers["Location"], "/login")

    def test_development_setup_rejects_non_local_clients(self):
        setup_database = Path(self.temp_dir.name) / "remote-setup.sqlite3"
        setup_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "unit-test-secret-key",
                "DATABASE": str(setup_database),
                "RATELIMIT_ENABLED": False,
            }
        )
        response = setup_app.test_client().get("/setup", environ_base={"REMOTE_ADDR": "192.0.2.10"})
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()