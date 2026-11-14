"""
app.py — NexusAI Intelligence Backend
Self-hosted Flask replacement for the Base44 app.

Features:
  - User registration, login, logout (session-based)
  - Password reset (token-based, logged to console)
  - Knowledge vault sections: HR, Finance, Product
  - AI chat endpoint (echo + keyword logic, swap in any LLM)
  - Human-oversight alert system: flags errors, sensitive changes,
    escalation keywords, and admin notifications
  - All alerts stored in-memory and shown in the dashboard
  - Pay stubs: employees view their own, employers can create/edit any

Run:
    python app.py
Then open: http://localhost:5000
"""

import os
import re
import uuid
import hashlib
import hmac
import json
import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, session,
    redirect, url_for, jsonify, flash
)
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "nexusai-dev-secret-change-in-prod")
CORS(app)

# ---------------------------------------------------------------------------
# In-memory stores (swap for a real DB in production)
# ---------------------------------------------------------------------------
USERS = {}          # username -> {password_hash, salt, email, role}
RESET_TOKENS = {}   # token -> {username, expires}
ALERTS = []         # list of alert dicts — human-oversight events
CHAT_HISTORY = {}   # username -> list of {role, content, ts}

# Pay stubs store: stub_id -> stub dict
# Fields: id, employee, employer_note, period_start, period_end,
#         gross_pay, deductions (list), net_pay, created_by, created_at, updated_at
PAY_STUBS = {}

def _new_stub_id():
    return str(uuid.uuid4())[:8].upper()

# Knowledge vault content
VAULT = {
    "hr": [
        {"title": "PTO Policy", "content": "Employees accrue 15 days PTO per year. Requests must be submitted 2 weeks in advance via the HR portal."},
        {"title": "Code of Conduct", "content": "All employees must adhere to respectful workplace standards. Violations should be reported to HR within 24 hours."},
        {"title": "Benefits Overview", "content": "Health, dental, and vision coverage begins on day 1. 401(k) matching up to 4% after 90 days."},
        {"title": "Onboarding Checklist", "content": "Complete I-9, set up SSO, attend orientation, meet your team lead within the first week."},
    ],
    "finance": [
        {"title": "Budget Cycle", "content": "Annual budget planning begins in October. Department heads submit forecasts by November 1."},
        {"title": "Expense Policy", "content": "Expenses over $500 require manager approval. All receipts must be submitted within 30 days."},
        {"title": "Procurement Process", "content": "Vendor selection requires 3 quotes for purchases over $5,000. Submit PO requests via the finance portal."},
        {"title": "Q3 Summary", "content": "Revenue: $4.2M (+12% YoY). Operating costs: $2.8M. Net margin: 33%."},
    ],
    "product": [
        {"title": "Roadmap Q4", "content": "Key deliverables: AI search v2, SSO integration, mobile app beta. Target release: Dec 15."},
        {"title": "API Documentation", "content": "REST API base URL: /api/v1. Authentication via Bearer token. Rate limit: 1000 req/hour."},
        {"title": "Release Notes v2.1", "content": "Fixed login timeout bug. Improved chat response latency by 40%. Added export to PDF."},
        {"title": "Design Guidelines", "content": "Primary color: #6C63FF. Font: Inter. All components follow WCAG 2.1 AA accessibility standards."},
    ],
}

# Keywords that trigger a human-oversight alert
ESCALATION_KEYWORDS = [
    "emergency", "urgent", "critical", "breach", "hack", "terminate",
    "lawsuit", "legal", "fire", "quit", "resign", "discrimination",
    "harassment", "error", "failed", "broken", "outage", "down"
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex(), dk.hex()


def _verify_password(stored_hash, stored_salt, provided):
    if not provided or not stored_hash or not stored_salt:
        return False
    try:
        salt_bytes = bytes.fromhex(stored_salt)
        expected = bytes.fromhex(stored_hash)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt_bytes, 260_000)
    return hmac.compare_digest(actual, expected)


def _add_alert(level, title, detail, username="system"):
    """Add a human-oversight alert."""
    ALERTS.insert(0, {
        "id": str(uuid.uuid4())[:8],
        "level": level,          # "info" | "warning" | "critical"
        "title": title,
        "detail": detail,
        "username": username,
        "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "acknowledged": False,
    })
    # Keep last 100 alerts
    if len(ALERTS) > 100:
        ALERTS.pop()


def _check_escalation(text, username):
    """Scan chat text for escalation keywords and raise alert if found."""
    lower = text.lower()
    triggered = [kw for kw in ESCALATION_KEYWORDS if kw in lower]
    if triggered:
        _add_alert(
            "warning",
            "Human Review Required",
            f"User '{username}' sent a message containing escalation keywords: {', '.join(triggered)}. Message: \"{text[:120]}\"",
            username=username,
        )
        return True
    return False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        user = USERS.get(session["username"], {})
        if user.get("role") != "admin":
            _add_alert("warning", "Unauthorized Admin Access Attempt",
                       f"User '{session['username']}' tried to access an admin page.",
                       username=session["username"])
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated


def employer_required(f):
    """Decorator: only users with role 'employer' or 'admin' may proceed."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        role = USERS.get(session["username"], {}).get("role", "user")
        if role not in ("employer", "admin"):
            _add_alert("warning", "Unauthorized Pay Stub Edit Attempt",
                       f"User '{session['username']}' (role={role}) tried to create/edit a pay stub.",
                       username=session["username"])
            flash("Only Employers can create or edit pay stubs.", "error")
            return redirect(url_for("paystubs"))
        return f(*args, **kwargs)
    return decorated


# Seed a default admin user and a demo employer on startup
def _seed_admin():
    salt, hsh = _hash_password("Admin@123")
    USERS["admin"] = {
        "password_hash": hsh, "salt": salt,
        "email": "admin@nexusai.local", "role": "admin",
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    # Demo employer account
    salt2, hsh2 = _hash_password("Employer@123")
    USERS["employer"] = {
        "password_hash": hsh2, "salt": salt2,
        "email": "employer@nexusai.local", "role": "employer",
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    # Demo employee account
    salt3, hsh3 = _hash_password("Employee@123")
    USERS["employee"] = {
        "password_hash": hsh3, "salt": salt3,
        "email": "employee@nexusai.local", "role": "user",
        "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    # Seed two sample pay stubs
    sid1 = _new_stub_id()
    PAY_STUBS[sid1] = {
        "id": sid1, "employee": "employee",
        "period_start": "2026-10-01", "period_end": "2026-10-15",
        "gross_pay": 3200.00,
        "deductions": [
            {"label": "Federal Tax", "amount": 480.00},
            {"label": "State Tax",   "amount": 160.00},
            {"label": "Health Ins.", "amount": 120.00},
        ],
        "net_pay": 2440.00,
        "employer_note": "Great work this period!",
        "created_by": "employer",
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": None,
    }
    sid2 = _new_stub_id()
    PAY_STUBS[sid2] = {
        "id": sid2, "employee": "employee",
        "period_start": "2026-10-16", "period_end": "2026-10-31",
        "gross_pay": 3200.00,
        "deductions": [
            {"label": "Federal Tax", "amount": 480.00},
            {"label": "State Tax",   "amount": 160.00},
            {"label": "Health Ins.", "amount": 120.00},
        ],
        "net_pay": 2440.00,
        "employer_note": "",
        "created_by": "employer",
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": None,
    }


_seed_admin()

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and _verify_password(user["password_hash"], user["salt"], password):
            session["username"] = username
            session["role"] = user.get("role", "user")
            _add_alert("info", "User Login", f"'{username}' logged in.", username=username)
            return redirect(url_for("home"))
        _add_alert("warning", "Failed Login Attempt",
                   f"Failed login attempt for username '{username}'.")
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if not username or not email or not password:
            flash("All fields are required.", "error")
        elif username in USERS:
            flash("Username already taken.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            salt, hsh = _hash_password(password)
            USERS[username] = {
                "password_hash": hsh, "salt": salt,
                "email": email, "role": "user",
                "created": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            _add_alert("info", "New User Registered", f"'{username}' ({email}) registered.", username=username)
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    username = session.pop("username", "unknown")
    session.pop("role", None)
    _add_alert("info", "User Logout", f"'{username}' logged out.", username=username)
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        matched = [(u, d) for u, d in USERS.items() if d["email"] == email]
        if matched:
            username, _ = matched[0]
            token = str(uuid.uuid4())
            expires = datetime.datetime.now() + datetime.timedelta(hours=1)
            RESET_TOKENS[token] = {"username": username, "expires": expires}
            # In production send via email — here we print to console
            reset_link = f"http://localhost:5000/reset-password/{token}"
            print(f"\n[PASSWORD RESET] User: {username} | Link: {reset_link}\n")
            _add_alert("info", "Password Reset Requested",
                       f"Reset requested for '{username}' ({email}).", username=username)
        # Always show the same message (don't leak whether email exists)
        flash("If that email is registered, a reset link has been printed to the server console.", "success")
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    entry = RESET_TOKENS.get(token)
    if not entry or datetime.datetime.now() > entry["expires"]:
        flash("Reset link is invalid or has expired.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            username = entry["username"]
            salt, hsh = _hash_password(password)
            USERS[username]["password_hash"] = hsh
            USERS[username]["salt"] = salt
            del RESET_TOKENS[token]
            _add_alert("warning", "Password Changed",
                       f"Password was reset for '{username}'.", username=username)
            flash("Password updated! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)


# ---------------------------------------------------------------------------
# Main app routes
# ---------------------------------------------------------------------------

@app.route("/home")
@login_required
def home():
    unacked = sum(1 for a in ALERTS if not a["acknowledged"])
    return render_template("home.html",
                           username=session["username"],
                           role=session.get("role"),
                           alert_count=unacked,
                           recent_alerts=ALERTS[:5])


@app.route("/vault/<section>")
@login_required
def vault(section):
    if section not in VAULT:
        flash("Unknown section.", "error")
        return redirect(url_for("home"))
    unacked = sum(1 for a in ALERTS if not a["acknowledged"])
    return render_template("vault.html",
                           section=section,
                           docs=VAULT[section],
                           username=session["username"],
                           role=session.get("role"),
                           alert_count=unacked)


@app.route("/chat")
@login_required
def chat():
    unacked = sum(1 for a in ALERTS if not a["acknowledged"])
    history = CHAT_HISTORY.get(session["username"], [])
    return render_template("chat.html",
                           username=session["username"],
                           role=session.get("role"),
                           history=history,
                           alert_count=unacked)


# ---------------------------------------------------------------------------
# Pay stub routes
# ---------------------------------------------------------------------------

@app.route("/paystubs")
@login_required
def paystubs():
    username = session["username"]
    role     = USERS.get(username, {}).get("role", "user")
    unacked  = sum(1 for a in ALERTS if not a["acknowledged"])
    # Employers/admins see all stubs; employees see only their own
    if role in ("employer", "admin"):
        stubs = sorted(PAY_STUBS.values(), key=lambda s: s["period_start"], reverse=True)
    else:
        stubs = sorted(
            [s for s in PAY_STUBS.values() if s["employee"] == username],
            key=lambda s: s["period_start"], reverse=True
        )
    return render_template("paystubs.html", stubs=stubs, role=role,
                           username=username, alert_count=unacked)


@app.route("/paystubs/new", methods=["GET", "POST"])
@login_required
@employer_required
def paystub_new():
    if request.method == "POST":
        f = request.form
        employee = f.get("employee", "").strip()
        if employee not in USERS:
            flash("Employee username not found.", "error")
            return render_template("paystub_edit.html", stub=None,
                                   users=list(USERS.keys()),
                                   username=session["username"],
                                   role=USERS.get(session["username"], {}).get("role"),
                                   alert_count=sum(1 for a in ALERTS if not a["acknowledged"]))
        # Parse deductions from form
        d_labels  = f.getlist("d_label")
        d_amounts = f.getlist("d_amount")
        deductions = []
        total_ded  = 0.0
        for lbl, amt in zip(d_labels, d_amounts):
            lbl = lbl.strip()
            if not lbl:
                continue
            try:
                a = round(float(amt), 2)
            except (ValueError, TypeError):
                a = 0.0
            deductions.append({"label": lbl, "amount": a})
            total_ded += a
        try:
            gross = round(float(f.get("gross_pay", 0)), 2)
        except (ValueError, TypeError):
            gross = 0.0
        net = round(gross - total_ded, 2)
        sid = _new_stub_id()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        PAY_STUBS[sid] = {
            "id": sid,
            "employee": employee,
            "period_start": f.get("period_start", ""),
            "period_end":   f.get("period_end", ""),
            "gross_pay":    gross,
            "deductions":   deductions,
            "net_pay":      net,
            "employer_note": f.get("employer_note", "").strip(),
            "created_by":   session["username"],
            "created_at":   now,
            "updated_at":   None,
        }
        _add_alert("info", "Pay Stub Created",
                   f"Employer '{session['username']}' created stub {sid} for employee '{employee}'.",
                   username=session["username"])
        flash(f"Pay stub {sid} created successfully.", "success")
        return redirect(url_for("paystubs"))

    unacked = sum(1 for a in ALERTS if not a["acknowledged"])
    return render_template("paystub_edit.html", stub=None,
                           users=list(USERS.keys()),
                           username=session["username"],
                           role=USERS.get(session["username"], {}).get("role"),
                           alert_count=unacked)


@app.route("/paystubs/<stub_id>/edit", methods=["GET", "POST"])
@login_required
@employer_required
def paystub_edit(stub_id):
    stub = PAY_STUBS.get(stub_id)
    if not stub:
        flash("Pay stub not found.", "error")
        return redirect(url_for("paystubs"))

    if request.method == "POST":
        f = request.form
        employee = f.get("employee", "").strip()
        if employee not in USERS:
            flash("Employee username not found.", "error")
        else:
            d_labels  = f.getlist("d_label")
            d_amounts = f.getlist("d_amount")
            deductions = []
            total_ded  = 0.0
            for lbl, amt in zip(d_labels, d_amounts):
                lbl = lbl.strip()
                if not lbl:
                    continue
                try:
                    a = round(float(amt), 2)
                except (ValueError, TypeError):
                    a = 0.0
                deductions.append({"label": lbl, "amount": a})
                total_ded += a
            try:
                gross = round(float(f.get("gross_pay", 0)), 2)
            except (ValueError, TypeError):
                gross = 0.0
            net = round(gross - total_ded, 2)
            stub.update({
                "employee":      employee,
                "period_start":  f.get("period_start", ""),
                "period_end":    f.get("period_end", ""),
                "gross_pay":     gross,
                "deductions":    deductions,
                "net_pay":       net,
                "employer_note": f.get("employer_note", "").strip(),
                "updated_at":    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            _add_alert("warning", "Pay Stub Edited",
                       f"Employer '{session['username']}' edited stub {stub_id} for '{employee}'.",
                       username=session["username"])
            flash(f"Pay stub {stub_id} updated.", "success")
            return redirect(url_for("paystubs"))

    unacked = sum(1 for a in ALERTS if not a["acknowledged"])
    return render_template("paystub_edit.html", stub=stub,
                           users=list(USERS.keys()),
                           username=session["username"],
                           role=USERS.get(session["username"], {}).get("role"),
                           alert_count=unacked)


@app.route("/paystubs/<stub_id>")
@login_required
def paystub_view(stub_id):
    stub = PAY_STUBS.get(stub_id)
    if not stub:
        flash("Pay stub not found.", "error")
        return redirect(url_for("paystubs"))
    username = session["username"]
    role     = USERS.get(username, {}).get("role", "user")
    # Employees can only view their own stubs
    if role not in ("employer", "admin") and stub["employee"] != username:
        flash("You can only view your own pay stubs.", "error")
        return redirect(url_for("paystubs"))
    unacked = sum(1 for a in ALERTS if not a["acknowledged"])
    return render_template("paystub_view.html", stub=stub, role=role,
                           username=username, alert_count=unacked)


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html",
                           alerts=ALERTS,
                           username=session["username"],
                           role=session.get("role"),
                           alert_count=len(ALERTS))


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    username = session["username"]
    if not message:
        return jsonify({"error": "Empty message"}), 400

    escalated = _check_escalation(message, username)

    # Simple keyword-based response engine (swap with OpenAI/watsonx call here)
    lower = message.lower()
    if any(w in lower for w in ["pto", "vacation", "time off", "leave"]):
        reply = "Per HR policy, employees accrue 15 days PTO per year. Submit requests 2 weeks in advance via the HR portal."
    elif any(w in lower for w in ["budget", "expense", "finance", "cost"]):
        reply = "The annual budget cycle begins in October. Expenses over $500 require manager approval."
    elif any(w in lower for w in ["roadmap", "product", "release", "api"]):
        reply = "Q4 key deliverables: AI search v2, SSO integration, mobile app beta (target Dec 15). API base: /api/v1."
    elif any(w in lower for w in ["hello", "hi", "hey", "help"]):
        reply = f"Hello {username}! I'm NexusAI. Ask me anything about HR policies, finance, or product updates."
    elif escalated:
        reply = "I've flagged your message for human review. A team member will follow up shortly."
    else:
        reply = f"I found no specific data for that query. Try asking about HR policies, budget guidelines, or the product roadmap."

    ts = datetime.datetime.now().strftime("%H:%M")
    history = CHAT_HISTORY.setdefault(username, [])
    history.append({"role": "user",    "content": message, "ts": ts})
    history.append({"role": "assistant","content": reply,   "ts": ts})
    # Keep last 50 messages
    CHAT_HISTORY[username] = history[-50:]

    return jsonify({"reply": reply, "escalated": escalated})


@app.route("/api/alerts/acknowledge/<alert_id>", methods=["POST"])
@login_required
def acknowledge_alert(alert_id):
    for alert in ALERTS:
        if alert["id"] == alert_id:
            alert["acknowledged"] = True
            return jsonify({"ok": True})
    return jsonify({"error": "Not found"}), 404


@app.route("/api/alerts/acknowledge-all", methods=["POST"])
@login_required
def acknowledge_all():
    for alert in ALERTS:
        alert["acknowledged"] = True
    return jsonify({"ok": True})


@app.route("/api/vault/search")
@login_required
def vault_search():
    q = request.args.get("q", "").lower()
    results = []
    for section, docs in VAULT.items():
        for doc in docs:
            if q in doc["title"].lower() or q in doc["content"].lower():
                results.append({"section": section, "title": doc["title"],
                                 "excerpt": doc["content"][:120] + "..."})
    return jsonify(results)


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  NexusAI Intelligence — http://localhost:5000")
    print("  Default admin login:  admin / Admin@123")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
