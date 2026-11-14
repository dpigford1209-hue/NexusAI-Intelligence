# NexusAI Intelligence — Self-Hosted
### A better-functioning replacement for the Base44 app

---

## Features

| Feature | Details |
|---|---|
| **Login / Logout** | Session-based authentication |
| **Register** | Create new user accounts |
| **Forgot Password** | Token-based reset (link printed to console) |
| **Knowledge Vault** | HR, Finance, and Product document sections with search |
| **AI Chat** | Conversational interface for company data queries |
| **Human Oversight Alerts** | Auto-flagged events: failed logins, escalation keywords, password changes, unauthorized access |
| **Acknowledge Alerts** | One-by-one or all-at-once |

---

## Requirements

- Python 3.8 or higher
- Flask + Flask-CORS (`pip install flask flask-cors`)

---

## Quick Start

```powershell
cd "C:\Users\User\OneDrive\NexusAI"
python app.py
```

Then open your browser to: **http://localhost:5000**

Default admin login:
- **Username:** `admin`
- **Password:** `Admin@123`

---

## Password Reset (self-hosted)

Since there is no email server configured, reset links are printed to the
terminal where `app.py` is running. After submitting the forgot-password form,
check the terminal for the link.

To add real email delivery, replace the `print(...)` line in `app.py`
(search for `[PASSWORD RESET]`) with an SMTP or SendGrid call.

---

## Human Oversight Alert Triggers

Alerts are automatically created for:

| Trigger | Level |
|---|---|
| Successful login | Info |
| Failed login attempt | Warning |
| New user registration | Info |
| Password reset requested | Info |
| Password changed | Warning |
| Unauthorized admin access attempt | Warning |
| Chat message contains escalation keywords | Warning |
| User logout | Info |

Escalation keywords include: `emergency`, `urgent`, `critical`, `breach`,
`hack`, `terminate`, `lawsuit`, `legal`, `fire`, `quit`, `resign`,
`discrimination`, `harassment`, `error`, `failed`, `broken`, `outage`, `down`

---

## Project Structure

```
NexusAI/
├── app.py                  # Flask backend — all routes and logic
├── templates/
│   ├── base.html           # Shared layout and navigation
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── forgot_password.html
│   ├── reset_password.html
│   ├── home.html           # Dashboard
│   ├── vault.html          # Knowledge vault (HR/Finance/Product)
│   ├── chat.html           # AI chat interface
│   └── alerts.html         # Human oversight alerts
└── README.md
```

---

## Production Notes

- Change `SECRET_KEY` via environment variable before deploying
- Replace in-memory `USERS` dict with a real database (SQLite/PostgreSQL)
- Add SMTP credentials to enable real password reset emails
- Run behind a reverse proxy (nginx) with HTTPS in production
