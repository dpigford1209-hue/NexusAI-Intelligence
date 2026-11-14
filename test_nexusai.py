"""
test_nexusai.py — NexusAI Intelligence Full Test Suite
Covers: auth, pay stubs, alerts, chat API, security, mobile meta tags.
Run: python test_nexusai.py
"""

import os, sys, json, unittest

os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["_TESTING"]   = "1"

sys.path.insert(0, os.path.dirname(__file__))
import app as nexus
from app import app as flask_app


class BaseCase(unittest.TestCase):
    def setUp(self):
        flask_app.config["TESTING"] = True
        flask_app.config["WTF_CSRF_ENABLED"] = False
        self.client = flask_app.test_client()
        # Reset shared state
        nexus.USERS.clear()
        nexus.ALERTS.clear()
        nexus.PAY_STUBS.clear()
        nexus.CHAT_HISTORY.clear()
        nexus.RESET_TOKENS.clear()
        nexus._seed_admin()

    def _login(self, username="admin", password="Admin@123"):
        return self.client.post("/login",
            data={"username": username, "password": password},
            follow_redirects=True)

    def _login_employer(self):
        return self._login("employer", "Employer@123")

    def _login_employee(self):
        return self._login("employee", "Employee@123")


# ===========================================================================
# AUTH TESTS (10)
# ===========================================================================
class TestAuth(BaseCase):

    def test_root_redirects_to_login(self):
        r = self.client.get("/", follow_redirects=False)
        self.assertIn(r.status_code, (301, 302))

    def test_login_page_loads(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"NexusAI", r.data)

    def test_valid_admin_login(self):
        r = self._login()
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Welcome back", r.data)

    def test_invalid_password_rejected(self):
        r = self.client.post("/login",
            data={"username": "admin", "password": "wrongpass"},
            follow_redirects=True)
        self.assertIn(b"Invalid username", r.data)

    def test_nonexistent_user_rejected(self):
        r = self.client.post("/login",
            data={"username": "ghost", "password": "whatever"},
            follow_redirects=True)
        self.assertIn(b"Invalid username", r.data)

    def test_register_new_user(self):
        r = self.client.post("/register", data={
            "username": "newuser", "email": "new@test.com",
            "password": "NewPass@1", "confirm": "NewPass@1"
        }, follow_redirects=True)
        self.assertIn(b"Account created", r.data)
        self.assertIn("newuser", nexus.USERS)

    def test_register_duplicate_username(self):
        r = self.client.post("/register", data={
            "username": "admin", "email": "x@x.com",
            "password": "NewPass@1", "confirm": "NewPass@1"
        }, follow_redirects=True)
        self.assertIn(b"already taken", r.data)

    def test_register_password_mismatch(self):
        r = self.client.post("/register", data={
            "username": "u2", "email": "u2@x.com",
            "password": "Pass@1234", "confirm": "Different@1"
        }, follow_redirects=True)
        self.assertIn(b"do not match", r.data)

    def test_logout_clears_session(self):
        self._login()
        r = self.client.get("/logout", follow_redirects=True)
        self.assertIn(b"logged out", r.data)
        # After logout, /home should redirect to login
        r2 = self.client.get("/home", follow_redirects=False)
        self.assertIn(r2.status_code, (301, 302))

    def test_forgot_password_page_loads(self):
        r = self.client.get("/forgot-password")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Reset Password", r.data)


# ===========================================================================
# SECURITY TESTS (10)
# ===========================================================================
class TestSecurity(BaseCase):

    def test_home_requires_login(self):
        r = self.client.get("/home", follow_redirects=False)
        self.assertIn(r.status_code, (301, 302))

    def test_chat_requires_login(self):
        r = self.client.get("/chat", follow_redirects=False)
        self.assertIn(r.status_code, (301, 302))

    def test_vault_requires_login(self):
        r = self.client.get("/vault/hr", follow_redirects=False)
        self.assertIn(r.status_code, (301, 302))

    def test_paystubs_requires_login(self):
        r = self.client.get("/paystubs", follow_redirects=False)
        self.assertIn(r.status_code, (301, 302))

    def test_paystub_new_requires_employer(self):
        """An employee (user role) must be blocked from creating pay stubs."""
        self._login_employee()
        r = self.client.get("/paystubs/new", follow_redirects=True)
        self.assertIn(b"Only Employers", r.data)

    def test_paystub_edit_requires_employer(self):
        """An employee must not be able to edit pay stubs."""
        self._login_employee()
        stubs = list(nexus.PAY_STUBS.keys())
        r = self.client.get(f"/paystubs/{stubs[0]}/edit", follow_redirects=True)
        self.assertIn(b"Only Employers", r.data)

    def test_employee_cannot_view_others_stub(self):
        """An employee must not see another employee's pay stub."""
        # Create a second employee and their stub
        s, h = nexus._hash_password("Test@1234")
        nexus.USERS["emp2"] = {"password_hash": h, "salt": s,
                               "email": "e2@t.com", "role": "user",
                               "created": "2026-01-01"}
        sid = nexus._new_stub_id()
        nexus.PAY_STUBS[sid] = {"id": sid, "employee": "emp2",
            "period_start": "2026-10-01", "period_end": "2026-10-15",
            "gross_pay": 1000, "deductions": [], "net_pay": 1000,
            "employer_note": "", "created_by": "employer",
            "created_at": "2026-10-01", "updated_at": None}
        self._login_employee()
        r = self.client.get(f"/paystubs/{sid}", follow_redirects=True)
        self.assertIn(b"own pay stubs", r.data)

    def test_failed_login_creates_alert(self):
        self.client.post("/login",
            data={"username": "admin", "password": "wrong"},
            follow_redirects=True)
        titles = [a["title"] for a in nexus.ALERTS]
        self.assertIn("Failed Login Attempt", titles)

    def test_chat_escalation_creates_alert(self):
        self._login()
        self.client.post("/api/chat",
            data=json.dumps({"message": "this is an emergency breach"}),
            content_type="application/json")
        titles = [a["title"] for a in nexus.ALERTS]
        self.assertIn("Human Review Required", titles)

    def test_password_reset_invalid_token(self):
        r = self.client.get("/reset-password/invalid-token-xyz",
                            follow_redirects=True)
        self.assertIn(b"invalid or has expired", r.data)


# ===========================================================================
# PAY STUB TESTS (8)
# ===========================================================================
class TestPayStubs(BaseCase):

    def test_employee_sees_own_stubs(self):
        self._login_employee()
        r = self.client.get("/paystubs")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Pay Stub", r.data)

    def test_employer_sees_all_stubs(self):
        self._login_employer()
        r = self.client.get("/paystubs")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"EMPLOYER VIEW", r.data)

    def test_employer_can_create_stub(self):
        self._login_employer()
        r = self.client.post("/paystubs/new", data={
            "employee": "employee",
            "period_start": "2026-11-01",
            "period_end":   "2026-11-15",
            "gross_pay": "2000.00",
            "d_label":  ["Federal Tax"],
            "d_amount": ["300.00"],
            "employer_note": "Good job",
        }, follow_redirects=True)
        self.assertIn(b"created successfully", r.data)
        self.assertGreater(len(nexus.PAY_STUBS), 2)

    def test_net_pay_calculated_correctly(self):
        self._login_employer()
        self.client.post("/paystubs/new", data={
            "employee": "employee",
            "period_start": "2026-11-01", "period_end": "2026-11-15",
            "gross_pay": "5000.00",
            "d_label":  ["Tax", "Health"],
            "d_amount": ["1000.00", "200.00"],
            "employer_note": "",
        }, follow_redirects=True)
        new_stub = sorted(nexus.PAY_STUBS.values(),
                          key=lambda s: s["created_at"])[-1]
        self.assertAlmostEqual(new_stub["net_pay"], 3800.00)

    def test_employer_can_edit_stub(self):
        self._login_employer()
        sid = list(nexus.PAY_STUBS.keys())[0]
        r = self.client.post(f"/paystubs/{sid}/edit", data={
            "employee": "employee",
            "period_start": "2026-10-01", "period_end": "2026-10-15",
            "gross_pay": "9999.00",
            "d_label":  [], "d_amount": [],
            "employer_note": "Updated",
        }, follow_redirects=True)
        self.assertIn(b"updated", r.data)
        self.assertAlmostEqual(nexus.PAY_STUBS[sid]["gross_pay"], 9999.00)

    def test_edit_creates_alert(self):
        self._login_employer()
        sid = list(nexus.PAY_STUBS.keys())[0]
        self.client.post(f"/paystubs/{sid}/edit", data={
            "employee": "employee",
            "period_start": "2026-10-01", "period_end": "2026-10-15",
            "gross_pay": "1.00",
            "d_label": [], "d_amount": [],
            "employer_note": "",
        }, follow_redirects=True)
        titles = [a["title"] for a in nexus.ALERTS]
        self.assertIn("Pay Stub Edited", titles)

    def test_view_nonexistent_stub_redirects(self):
        self._login_employer()
        r = self.client.get("/paystubs/FAKEID", follow_redirects=True)
        self.assertIn(b"not found", r.data)

    def test_paystub_view_loads(self):
        self._login_employee()
        sid = [s["id"] for s in nexus.PAY_STUBS.values()
               if s["employee"] == "employee"][0]
        r = self.client.get(f"/paystubs/{sid}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Net Pay", r.data)


# ===========================================================================
# CHAT API TESTS (5)
# ===========================================================================
class TestChatAPI(BaseCase):

    def _chat(self, msg):
        return self.client.post("/api/chat",
            data=json.dumps({"message": msg}),
            content_type="application/json")

    def test_chat_requires_login(self):
        r = self._chat("hello")
        self.assertIn(r.status_code, (301, 302))

    def test_chat_hr_keyword(self):
        self._login()
        r = self._chat("what is the PTO policy")
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.data)
        self.assertIn("PTO", data["reply"])

    def test_chat_finance_keyword(self):
        self._login()
        r = self._chat("tell me about the budget")
        data = json.loads(r.data)
        self.assertIn("budget", data["reply"].lower())

    def test_chat_escalation_flagged(self):
        self._login()
        r = self._chat("we have a critical outage emergency")
        data = json.loads(r.data)
        self.assertTrue(data["escalated"])

    def test_chat_empty_message_rejected(self):
        self._login()
        r = self._chat("")
        self.assertEqual(r.status_code, 400)


# ===========================================================================
# ALERTS TESTS (4)
# ===========================================================================
class TestAlerts(BaseCase):

    def test_alerts_page_loads(self):
        self._login()
        r = self.client.get("/alerts")
        self.assertEqual(r.status_code, 200)

    def test_acknowledge_single_alert(self):
        self._login()
        aid = nexus.ALERTS[0]["id"]
        r = self.client.post(f"/api/alerts/acknowledge/{aid}")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(nexus.ALERTS[0]["acknowledged"])

    def test_acknowledge_all_alerts(self):
        self._login()
        r = self.client.post("/api/alerts/acknowledge-all")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(all(a["acknowledged"] for a in nexus.ALERTS))

    def test_invalid_alert_id_returns_404(self):
        self._login()
        r = self.client.post("/api/alerts/acknowledge/BADID")
        self.assertEqual(r.status_code, 404)


# ===========================================================================
# MOBILE / RESPONSIVENESS TESTS (3)
# ===========================================================================
class TestMobileReadiness(BaseCase):

    def _get_login_html(self):
        return self.client.get("/login").data.decode()

    def test_viewport_meta_tag_present(self):
        """Mobile responsiveness requires a viewport meta tag."""
        html = self._get_login_html()
        self.assertIn('name="viewport"', html)
        self.assertIn("width=device-width", html)

    def test_mobile_web_app_capable_meta(self):
        """iOS home-screen / PWA support meta tag present."""
        html = self._get_login_html()
        self.assertIn("mobile-web-app-capable", html)

    def test_no_fixed_pixel_widths_on_login(self):
        """Login page must use max-width, not a hard pixel width that breaks on small screens."""
        html = self._get_login_html()
        self.assertIn("max-width", html)
        # Should NOT force a fixed 1200px+ width
        self.assertNotIn("width:1200px", html)
        self.assertNotIn("width: 1200px", html)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    unittest.main(verbosity=2)
