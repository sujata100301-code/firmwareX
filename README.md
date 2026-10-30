# FirmwareX Workbench

FirmwareX is a private-login dashboard prototype for licensed, open-source IoT firmware research. It includes a real server-side authentication boundary and synthetic dashboard data. Firmware extraction, emulation, symbolic analysis, fuzzing, and report generation are not connected yet.

## Local setup

Requires Python 3.13 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FIRMWAREX_SECRET_KEY = (& python -c "import secrets; print(secrets.token_hex(32))").Trim()
$env:COOKIE_SECURE = "0"
python -m flask --app app run --host 127.0.0.1 --port 4173
```

Visit `http://localhost:4173/login` and choose **First time here? Set up the administrator account**. The first-run form is available only from localhost in development, requires a password of at least 14 characters, and closes once the first account is created. There is no public registration or default account. This local HTTP mode is only for local testing; do not use it to submit credentials from other devices or across a public network. For internet access, deploy behind HTTPS as described below.

Run the auth tests with:

```powershell
python -m unittest discover -s tests -v
```

## Internet deployment

Deploy the Docker image to a platform that supports containers, persistent storage, environment variables, and a managed Redis-compatible service. Configure the variables shown in `.env.example`; generate fresh random values for `FIRMWAREX_SECRET_KEY` and `FIRMWAREX_SETUP_TOKEN`, set `TRUSTED_HOSTS` to the exact public hostname(s), and point `RATELIMIT_STORAGE_URI` at private Redis. Mount persistent storage at `/data` for the SQLite account database. Visit `/setup` over HTTPS and enter the setup token and first account details. Setup closes automatically after the first account is created; remove `FIRMWAREX_SETUP_TOKEN` from the deployment environment afterward.

Terminate TLS at the hosting platform or trusted reverse proxy and enforce HTTPS redirects there. Set `TRUST_PROXY=1` only when exactly one trusted proxy sets the standard forwarded headers. Keep the application and Redis private behind the platform ingress. Do not use the Flask development server or expose Redis publicly. The login protects the dashboard; the current prototype still has no role management, password reset, MFA, or self-service registration.

## Authentication controls

- Passwords use Werkzeug's scrypt password hash; plaintext passwords are never stored.
- Sessions are HTTP-only, SameSite=Lax, non-remembered, and expire after eight hours. Secure cookies are mandatory in production.
- Login and logout use CSRF tokens; logout is POST-only.
- Login is limited to five attempts per minute per client IP. Production refuses in-memory rate-limit storage so limits remain effective across workers.
- Production startup requires a 32-character secret, explicit trusted hosts, and shared rate-limit storage.
- Security headers include a restrictive content policy, clickjacking protection, no-sniff, and HSTS on HTTPS requests.

## Dashboard and analysis boundaries

- Overview, analysis list, CWE findings, artifact tree, binary-hardening matrix, illustrative CFG, and sandbox status use synthetic sample records.
- The intake dialog does not upload, unpack, or execute a selected file.
- Keep any future analysis API and workers on a separate private network. Workers must have no route to live devices or external networks, use strict CPU/memory/time budgets and disposable filesystems, and accept only licensed public firmware inputs.
- Findings are diagnostic leads for human validation, not proof of exploitability or functional exploit material.