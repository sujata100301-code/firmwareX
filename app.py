import argparse
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Iterator
from urllib.parse import urljoin, urlparse

from flask import Flask, abort, current_app, flash, redirect, render_template, request, send_from_directory, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
INSTANCE_DIR = ROOT / "instance"

login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


class User(UserMixin):
    def __init__(self, user_id: int, username: str, password_hash: str) -> None:
        self.id = str(user_id)
        self.username = username
        self.password_hash = password_hash


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(current_app.config["DATABASE"])
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    database_path = Path(current_app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )


def find_user_by_name(username: str) -> User | None:
    with get_db() as connection:
        row = connection.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()
    if row is None:
        return None
    return User(row["id"], row["username"], row["password_hash"])


def add_user(username: str, password: str) -> None:
    username = username.strip()
    if not 3 <= len(username) <= 64 or any(char.isspace() for char in username):
        raise ValueError("Username must be 3-64 characters with no spaces.")
    if len(password) < 14:
        raise ValueError("Password must be at least 14 characters.")
    with get_db() as connection:
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password, method="scrypt")),
        )


def has_users() -> bool:
    with get_db() as connection:
        return connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def add_initial_user(username: str, password: str) -> None:
    username = username.strip()
    if not 3 <= len(username) <= 64 or any(char.isspace() for char in username):
        raise ValueError("Username must be 3-64 characters with no spaces.")
    if len(password) < 14:
        raise ValueError("Password must be at least 14 characters.")
    with get_db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
            raise ValueError("Initial setup has already been completed.")
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password, method="scrypt")),
        )


def safe_redirect_target(target: str | None) -> str | None:
    if not target:
        return None
    base = urlparse(request.host_url)
    destination = urlparse(urljoin(request.host_url, target))
    if destination.scheme in {"http", "https"} and destination.netloc == base.netloc:
        return target
    return None


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder="public", static_folder=None)
    production = os.getenv("APP_ENV", "development").lower() == "production"
    secret_key = os.getenv("FIRMWAREX_SECRET_KEY")
    trusted_hosts = [host.strip() for host in os.getenv("TRUSTED_HOSTS", "").split(",") if host.strip()]
    rate_limit_storage = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

    if not secret_key and test_config is None:
        raise RuntimeError("Set FIRMWAREX_SECRET_KEY to a randomly generated secret (at least 32 characters).")
    if production and len(secret_key or "") < 32:
        raise RuntimeError("Production requires FIRMWAREX_SECRET_KEY with at least 32 characters.")
    if production and not trusted_hosts:
        raise RuntimeError("Production requires TRUSTED_HOSTS with the site's host name(s).")
    if production and rate_limit_storage.startswith("memory://"):
        raise RuntimeError("Production requires a shared RATELIMIT_STORAGE_URI such as Redis.")

    app.config.update(
        SECRET_KEY=secret_key or "test-only-key",
        DATABASE=os.getenv("FIRMWAREX_DATABASE", str(INSTANCE_DIR / "firmwarex.sqlite3")),
        TRUSTED_HOSTS=trusted_hosts or None,
        SESSION_COOKIE_NAME="firmwarex_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=production or os.getenv("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        SESSION_REFRESH_EACH_REQUEST=False,
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI=rate_limit_storage,
        RATELIMIT_DEFAULT="200 per hour",
        RATELIMIT_HEADERS_ENABLED=True,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    if os.getenv("TRUST_PROXY", "0") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"
    csrf.init_app(app)
    limiter.init_app(app)

    with app.app_context():
        init_db()

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        try:
            numeric_id = int(user_id)
        except (TypeError, ValueError):
            return None
        with get_db() as connection:
            row = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE id = ?",
                (numeric_id,),
            ).fetchone()
        if row is None:
            return None
        return User(row["id"], row["username"], row["password_hash"])

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.get("/healthz")
    @limiter.exempt
    def healthz():
        return {"status": "ok"}

    @app.route("/setup", methods=["GET", "POST"])
    @limiter.limit("5 per hour", methods=["POST"])
    def setup():
        if has_users():
            return redirect(url_for("login"))
        if not production and request.remote_addr not in {"127.0.0.1", "::1"}:
            abort(404)
        if production and request.method == "POST":
            expected_token = os.getenv("FIRMWAREX_SETUP_TOKEN", "")
            provided_token = request.form.get("setup_token", "")
            if len(expected_token) < 32 or not secrets.compare_digest(expected_token, provided_token):
                abort(404)
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            confirmation = request.form.get("confirm_password", "")
            if not secrets.compare_digest(password, confirmation):
                flash("The passwords do not match.", "error")
            else:
                try:
                    add_initial_user(username, password)
                except (sqlite3.IntegrityError, ValueError) as error:
                    flash(str(error), "error")
                else:
                    flash("Administrator account created. Sign in to continue.", "success")
                    return redirect(url_for("login"))
        return render_template("setup.html", production=production)

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        next_target = safe_redirect_target(request.values.get("next"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = find_user_by_name(username)
            if user is not None and check_password_hash(user.password_hash, password):
                login_user(user, remember=False, fresh=True)
                session.permanent = True
                return redirect(next_target or url_for("dashboard"))
            flash("The username or password was not recognized.", "error")
        return render_template("login.html", next_target=next_target or "", setup_available=not has_users())

    @app.post("/logout")
    @require_auth
    def logout():
        logout_user()
        flash("You have signed out.", "success")
        return redirect(url_for("login"))

    @app.get("/")
    @require_auth
    def dashboard():
        return render_template("index.html")

    @app.get("/styles.css")
    @require_auth
    def dashboard_styles():
        return send_from_directory(PUBLIC_DIR, "styles.css", mimetype="text/css")

    @app.get("/app.js")
    @require_auth
    def dashboard_script():
        return send_from_directory(PUBLIC_DIR, "app.js", mimetype="text/javascript")

    @app.get("/login.css")
    def login_styles():
        return send_from_directory(PUBLIC_DIR, "login.css", mimetype="text/css")

    return app


app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="FirmwareX account administration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_user_parser = subparsers.add_parser("create-user", help="Create a dashboard login")
    create_user_parser.add_argument("username")
    args = parser.parse_args()

    if args.command == "create-user":
        import getpass

        password = getpass.getpass("New password (14+ characters): ")
        confirmation = getpass.getpass("Confirm password: ")
        if not secrets.compare_digest(password, confirmation):
            parser.error("Passwords do not match.")
        try:
            add_user(args.username, password)
        except (sqlite3.IntegrityError, ValueError) as error:
            parser.error(str(error))
        print(f"Created dashboard user {args.username.strip()}.")


if __name__ == "__main__":
    main()