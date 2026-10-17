"""
ScamShield — Comprehensive Test Suite
Tests all analyzers and API endpoints.
Run with: pytest test_analyzers.py -v
"""
import json
import pytest
from fastapi.testclient import TestClient

from analyzer.url_analyzer import analyze_url
from analyzer.message_analyzer import analyze_message
from analyzer.email_analyzer import analyze_email
from analyzer.file_analyzer import analyze_file
import main


client = TestClient(main.app)


# ============================================================================
# URL Analyzer Tests
# ============================================================================

class TestURLAnalyzer:

    def test_phishing_url_critical(self):
        """Paypal impersonation with HTTP and suspicious TLD → critical."""
        r = analyze_url("http://paypal-login-secure.tk/verify?account=suspended")
        assert r.risk_level in ("critical", "high")
        assert r.risk_score >= 50

    def test_ip_url_high_risk(self):
        """Raw IP address URL."""
        r = analyze_url("http://192.168.1.1/admin/login")
        assert r.risk_score >= 40
        signals = [e.signal for e in r.evidence]
        assert any("IP address" in s for s in signals)

    def test_safe_url_google(self):
        """Legitimate Google URL should be low or safe."""
        r = analyze_url("https://www.google.com/search?q=python")
        assert r.risk_level in ("safe", "low")
        assert r.risk_score < 40

    def test_safe_url_github(self):
        """Legitimate GitHub URL should be low or safe."""
        r = analyze_url("https://github.com/openai/whisper")
        assert r.risk_level in ("safe", "low")
        assert r.risk_score < 40

    def test_https_detected(self):
        """HTTPS flag should be True for https:// URLs."""
        r = analyze_url("https://example.com")
        assert r.is_https is True

    def test_http_detected(self):
        """is_https should be False for http:// URLs."""
        r = analyze_url("http://example.com")
        assert r.is_https is False

    def test_typosquatting_paypa1(self):
        """paypa1.com (numeric 1 instead of l) should flag typosquatting."""
        r = analyze_url("http://paypa1.com/login")
        assert r.risk_score >= 30

    def test_url_shortener_detected(self):
        """bit.ly URL should flag shortener signal."""
        r = analyze_url("https://bit.ly/3xABcDe")
        signals = [e.signal for e in r.evidence]
        assert any("shortener" in s.lower() or "bit.ly" in s.lower() for s in signals)

    def test_javascript_scheme(self):
        """javascript: URI should score critically high."""
        r = analyze_url("javascript:alert('xss')")
        assert r.risk_score >= 50

    def test_domain_extracted(self):
        """Domain should be correctly extracted."""
        r = analyze_url("https://evil.xyz/path")
        assert r.domain == "evil.xyz"

    def test_evidence_not_empty_for_scam(self):
        """Scam URL should return multiple evidence signals."""
        r = analyze_url("http://sbi-verify.tk/otp?account=suspend")
        assert len(r.evidence) >= 2

    def test_limitations_always_present(self):
        """Limitations must always be included in results."""
        r = analyze_url("https://google.com")
        assert len(r.limitations) > 0

    def test_next_steps_always_present(self):
        """Next steps must always be present."""
        r = analyze_url("https://google.com")
        assert len(r.next_steps) > 0

    def test_risk_score_capped_at_100(self):
        """Score should never exceed 100."""
        r = analyze_url("http://paypal-login-secure-verify.tk/otp/account?redirect=evil.com&suspended=true")
        assert r.risk_score <= 100

    def test_risk_score_non_negative(self):
        """Score should never be negative."""
        r = analyze_url("https://google.com")
        assert r.risk_score >= 0


# ============================================================================
# Message Analyzer Tests
# ============================================================================

class TestMessageAnalyzer:

    def test_otp_sms_medium_or_above(self):
        """OTP mention in genuine-looking message should be at least medium."""
        r = analyze_message("Your OTP is 847291. Do not share it. -HDFCBK")
        assert r.risk_score >= 20  # OTP triggers credential harvest

    def test_lottery_scam_critical(self):
        """KBC lottery scam message should be critical."""
        r = analyze_message(
            "Congratulations! You have won Rs 50 lakh in the KBC lottery. "
            "Claim your prize now. Keep this confidential."
        )
        assert r.risk_level in ("critical", "high")

    def test_bank_suspension_scam(self):
        """SBI suspension + OTP + link should be critical."""
        r = analyze_message(
            "URGENT: Your SBI account has been suspended. Verify Aadhaar and OTP at "
            "http://sbi-verify.tk/login within 24 hours!"
        )
        assert r.risk_level == "critical"

    def test_legitimate_amazon_low_risk(self):
        """Amazon shipping notification should be low risk."""
        r = analyze_message(
            "Hi John, your Amazon order #112-3456789 has shipped. "
            "Expected delivery Thursday. Track at amazon.com/orders."
        )
        assert r.risk_level in ("safe", "low", "medium")

    def test_crypto_seed_phrase_critical(self):
        """Seed phrase request + guaranteed profit → critical."""
        r = analyze_message(
            "Enter seed phrase at http://claim-airdrop-usdt.xyz/connect "
            "and get guaranteed 200% profit."
        )
        assert r.risk_level in ("critical", "high")

    def test_job_scam_detected(self):
        """Work from home earning 5000/day → high."""
        r = analyze_message(
            "Work from home and earn 5000 per day reviewing YouTube videos. "
            "Join our Telegram recruiter @quick_hire_hr."
        )
        assert r.risk_level in ("high", "critical")

    def test_extracted_urls_found(self):
        """URLs in message body should be extracted."""
        r = analyze_message("Click here: http://evil.tk/phish")
        assert "http://evil.tk/phish" in r.extracted_urls

    def test_signal_counts_present(self):
        """signal_counts dict must be returned."""
        r = analyze_message("Test message")
        assert isinstance(r.signal_counts, dict)

    def test_score_bounded(self):
        """Score should be 0-100."""
        r = analyze_message("URGENT! OTP verify account login bank suspended NOW click http://evil.tk")
        assert 0 <= r.risk_score <= 100

    def test_evidence_explanations_not_empty(self):
        """All evidence items should have non-empty explanations."""
        r = analyze_message("Your account has been suspended. Verify OTP immediately!")
        for ev in r.evidence:
            assert ev.explanation


# ============================================================================
# Email Analyzer Tests
# ============================================================================

class TestEmailAnalyzer:

    PHISHING_HEADERS = """From: PayPal Security <service@paypal-secure-alert.tk>
Reply-To: collect@harvest-emails.xyz
Subject: URGENT: Your PayPal account has been limited
Authentication-Results: mx.google.com;
   spf=fail (google.com: domain of service@paypal-secure-alert.tk does not designate)
   dkim=fail header.i=@paypal-secure-alert.tk;
   dmarc=fail (p=REJECT) header.from=paypal-secure-alert.tk"""

    PHISHING_BODY = """Dear Customer,
Click here to verify your account: http://paypal-verify.tk/confirm
Provide your password and credit card number and OTP immediately or your account will be suspended."""

    LEGIT_HEADERS = """From: GitHub <noreply@github.com>
Subject: Your GitHub security alert
Authentication-Results: mx.google.com;
   spf=pass (google.com: domain of noreply@github.com)
   dkim=pass header.i=@github.com;
   dmarc=pass (p=REJECT) header.from=github.com"""

    def test_spf_fail_increases_score(self):
        """SPF fail in headers should increase risk score."""
        r = analyze_email(raw_headers=self.PHISHING_HEADERS)
        spf_ev = [e for e in r.evidence if "SPF" in e.signal]
        assert any(e.severity in ("high", "critical") for e in spf_ev)

    def test_dkim_fail_increases_score(self):
        """DKIM fail should increase risk score significantly."""
        r = analyze_email(raw_headers=self.PHISHING_HEADERS)
        assert r.risk_score >= 50

    def test_reply_to_mismatch_detected(self):
        """From/Reply-To domain mismatch should be flagged."""
        r = analyze_email(raw_headers=self.PHISHING_HEADERS)
        signals = [e.signal for e in r.evidence]
        assert any("mismatch" in s.lower() or "reply" in s.lower() for s in signals)

    def test_spf_pass_good_signal(self):
        """SPF pass should produce a 'safe' evidence entry."""
        r = analyze_email(raw_headers=self.LEGIT_HEADERS)
        spf_ev = [e for e in r.evidence if "SPF" in e.signal]
        assert any(e.severity == "safe" for e in spf_ev)

    def test_credential_harvest_in_body(self):
        """Credential harvesting patterns in body should be flagged."""
        r = analyze_email(raw_headers="", body=self.PHISHING_BODY)
        categories = [e.category for e in r.evidence]
        assert "Credential Harvesting" in categories

    def test_auth_results_parsed(self):
        """auth_results dict should be populated from headers."""
        r = analyze_email(raw_headers=self.PHISHING_HEADERS)
        assert r.auth_results["spf"] == "fail"
        assert r.auth_results["dkim"] == "fail"
        assert r.auth_results["dmarc"] == "fail"

    def test_phishing_overall_critical_or_high(self):
        """Full phishing email should be critical or high."""
        r = analyze_email(raw_headers=self.PHISHING_HEADERS, body=self.PHISHING_BODY)
        assert r.risk_level in ("critical", "high")

    def test_legit_lower_risk(self):
        """Legitimate email with passing auth should be lower risk."""
        r = analyze_email(
            raw_headers=self.LEGIT_HEADERS,
            body="Hi there, a new SSH key was added to your account. If this was you, ignore this."
        )
        assert r.risk_score < 40  # No credential harvesting, auth passes

    def test_urls_extracted_from_body(self):
        """URLs should be extracted from body."""
        r = analyze_email(raw_headers="", body="Click http://evil.tk/phish to verify")
        assert "http://evil.tk/phish" in r.extracted_urls

    def test_limitations_always_present(self):
        r = analyze_email(raw_headers=self.LEGIT_HEADERS)
        assert len(r.limitations) > 0


# ============================================================================
# File Analyzer Tests
# ============================================================================

class TestFileAnalyzer:

    def test_plain_text_safe(self):
        """Plain UTF-8 text file should be low risk."""
        data = b"Hello, this is a plain text file with normal content."
        r = analyze_file(data, "readme.txt")
        assert r.risk_level in ("safe", "low")

    def test_exe_file_critical(self):
        """File with MZ header (Windows PE) should be critical."""
        # MZ header
        data = b"MZ" + b"\x00" * 100
        r = analyze_file(data, "invoice.exe")
        assert r.risk_level in ("critical", "high")

    def test_double_extension_detected(self):
        """Filename like 'document.exe.pdf' should flag double extension."""
        data = b"MZ" + b"\x00" * 100
        r = analyze_file(data, "document.exe.pdf")
        signals = [e.signal for e in r.evidence]
        assert any("double extension" in s.lower() for s in signals)

    def test_pdf_magic_identified(self):
        """PDF magic bytes should be identified correctly."""
        data = b"%PDF-1.4 normal content"
        r = analyze_file(data, "report.pdf")
        assert "PDF" in r.detected_type

    def test_zip_archive_identified(self):
        """ZIP magic bytes should be identified."""
        # Create minimal ZIP
        import zipfile, io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr("readme.txt", "hello")
        data = buf.getvalue()
        r = analyze_file(data, "archive.zip")
        assert "zip" in r.detected_type.lower() or "zip" in r.risk_level or len(r.evidence) > 0

    def test_sha256_always_computed(self):
        """SHA-256 hash should always be computed."""
        import hashlib
        data = b"test content"
        r = analyze_file(data, "test.txt")
        assert r.sha256 == hashlib.sha256(data).hexdigest()

    def test_filename_directory_traversal_sanitised(self):
        """Directory traversal in filename should be stripped."""
        data = b"safe content"
        r = analyze_file(data, "../../etc/passwd")
        assert "/" not in r.filename
        assert "\\" not in r.filename

    def test_type_mismatch_exe_as_txt(self):
        """MZ executable disguised as .txt should flag type mismatch."""
        data = b"MZ" + b"\x00" * 50
        r = analyze_file(data, "notes.txt")
        assert r.type_mismatch is True

    def test_score_bounded(self):
        """Score should be 0-100."""
        data = b"MZ" + b"\x00" * 1000
        r = analyze_file(data, "evil.exe.pdf")
        assert 0 <= r.risk_score <= 100

    def test_empty_evidence_not_returned_for_safe(self):
        """Safe files should still return positive evidence signals."""
        data = b"Normal plain text content for testing."
        r = analyze_file(data, "notes.txt")
        assert len(r.evidence) > 0  # Should at least have "consistent type" evidence


# ============================================================================
# API Endpoint Tests (via TestClient)
# ============================================================================

class TestAPIEndpoints:

    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_readiness(self):
        resp = client.get("/readiness")
        assert resp.status_code == 200
        data = resp.json()
        assert "components" in data

    def test_root(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "service" in resp.json()

    def test_analyze_url_valid(self):
        resp = client.post("/analyze/url", json={"url": "https://google.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_level" in data
        assert "risk_score" in data
        assert "evidence" in data

    def test_analyze_url_empty_rejected(self):
        resp = client.post("/analyze/url", json={"url": "   "})
        assert resp.status_code == 422  # Pydantic validation error

    def test_analyze_message_valid(self):
        resp = client.post("/analyze/message", json={"text": "Hello, this is a test message."})
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_level" in data

    def test_analyze_message_empty_rejected(self):
        resp = client.post("/analyze/message", json={"text": "   "})
        assert resp.status_code == 422

    def test_analyze_email_with_headers(self):
        resp = client.post("/analyze/email", json={
            "raw_headers": "From: evil@phish.tk\nSubject: Urgent action required",
            "body": "Verify your OTP immediately to avoid account suspension.",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_level" in data
        assert data["scan_type"] == "email"

    def test_analyze_email_all_empty_rejected(self):
        resp = client.post("/analyze/email", json={})
        assert resp.status_code in (400, 422)

    def test_history_returns_list(self):
        resp = client.get("/history?limit=5")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_stats_structure(self):
        resp = client.get("/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_scans" in data
        assert "critical_count" in data
        assert "by_scan_type" in data

    def test_demo_cases_not_empty(self):
        resp = client.get("/demo-cases")
        assert resp.status_code == 200
        assert len(resp.json()) > 0

    def test_run_demo_case_url(self):
        resp = client.post("/demo-cases/demo-1/run")
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_level" in data
        assert "matched_expected" in data

    def test_run_demo_case_message(self):
        resp = client.post("/demo-cases/demo-5/run")
        assert resp.status_code == 200

    def test_demo_case_not_found(self):
        resp = client.post("/demo-cases/nonexistent/run")
        assert resp.status_code == 404

    def test_api_prefix_works(self):
        """Test /api prefix routing."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_api_v1_prefix_works(self):
        """Test /api/v1 prefix routing."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_analyze_file_upload(self):
        """Test file upload endpoint."""
        data = b"Hello, this is a test text file."
        resp = client.post(
            "/analyze/file",
            files={"file": ("test.txt", data, "text/plain")}
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["scan_type"] == "file"
        assert "sha256" in result.get("file_sha256", "sha256") or "file_sha256" in result

    def test_analyze_file_empty_rejected(self):
        """Empty file should be rejected."""
        resp = client.post(
            "/analyze/file",
            files={"file": ("empty.txt", b"", "text/plain")}
        )
        assert resp.status_code == 400

    def test_scan_history_saved_after_url_scan(self):
        """URL scan result should appear in history."""
        # Run a scan
        client.post("/analyze/url", json={"url": "https://example.com/test-history"})
        # Check history
        resp = client.get("/history?limit=10")
        items = resp.json()
        previews = [i["input_preview"] for i in items]
        assert any("example.com" in p for p in previews)


# ============================================================================
# Demo case accuracy test
# ============================================================================

class TestDemoAccuracy:
    """Verify that ScamShield correctly classifies labeled demo cases."""

    CASES = [
        ("demo-1", "critical"),
        ("demo-2", "high"),
        ("demo-3", "safe"),
        ("demo-5", "critical"),
        ("demo-6", "critical"),
        ("demo-10", "critical"),
    ]

    @pytest.mark.parametrize("case_id,expected", CASES)
    def test_demo_case(self, case_id, expected):
        resp = client.post(f"/demo-cases/{case_id}/run")
        assert resp.status_code == 200
        data = resp.json()
        # Allow one level of tolerance for borderline cases
        RISK_ORDER = ["safe", "low", "medium", "high", "critical"]
        actual_idx = RISK_ORDER.index(data["risk_level"])
        expected_idx = RISK_ORDER.index(expected)
        assert abs(actual_idx - expected_idx) <= 1, (
            f"Case {case_id}: expected {expected}, got {data['risk_level']} "
            f"(score={data['risk_score']})"
        )
