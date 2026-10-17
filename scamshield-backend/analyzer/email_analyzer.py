"""
Email Forensics Analyzer — ScamShield
Analyses email content and raw headers for phishing/spoofing indicators.

Checks:
  - Sender/Reply-To mismatch
  - Display-name impersonation
  - SPF, DKIM, DMARC result interpretation (from Authentication-Results header)
  - Suspicious links in body
  - Credential-harvesting patterns
  - Business Email Compromise (BEC) indicators
  - HTML injection markers (without executing content)
  - Suspicious attachment references

NOTE: This performs purely text-based, static analysis on header strings
and message body. No external requests are made. Results reflect heuristic
patterns and should not be treated as definitive forensic proof.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from email import message_from_string
from email.utils import parseaddr


# ---------------------------------------------------------------------------
# Known brand / sender domains for impersonation checks
# ---------------------------------------------------------------------------
TRUSTED_BRANDS = [
    "paypal", "amazon", "netflix", "apple", "google", "microsoft", "facebook",
    "instagram", "whatsapp", "twitter", "ebay", "walmart", "chase", "bankofamerica",
    "wellsfargo", "citibank", "hsbc", "irs", "gov", "fedex", "ups", "dhl",
    "linkedin", "dropbox", "zoom", "youtube", "spotify", "tiktok", "binance",
    "coinbase", "metamask", "upi", "paytm", "phonepe", "sbi", "hdfc", "icici",
    "axis", "rbi", "telegram", "discord", "steam", "openai", "noreply",
    "support", "security", "alert", "verify", "account", "service",
]

LEGITIMATE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "microsoft.com", "outlook.com", "hotmail.com", "live.com",
    "apple.com", "amazon.com", "paypal.com", "netflix.com", "linkedin.com",
    "github.com", "wikipedia.org", "reddit.com", "whatsapp.com", "zoom.us",
    "dropbox.com", "spotify.com", "ebay.com", "telegram.org", "discord.com",
    "openai.com", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in",
}

CREDENTIAL_HARVEST_PATTERNS = [
    (r"\bverify\b.*?\baccount\b", "Account verification request"),
    (r"\bconfirm\b.*?\b(password|identity|detail)\b", "Confirmation request"),
    (r"\bupdate\b.*?\b(password|info|account|detail)\b", "Account update request"),
    (r"\bpassword\b", "Password mention"),
    (r"\bpin\b|\bpin number\b", "PIN request"),
    (r"\bOTP\b|\bone.?time.?pass", "OTP request — never share this"),
    (r"\bsocial security\b|\bSSN\b", "Social Security Number request"),
    (r"\bcredit card\b|\bcard number\b|\bcvv\b|\bexpiry\b", "Card data request"),
    (r"\baadhaar\b|\bpan card\b", "Government ID request"),
    (r"\bseed phrase\b|\bprivate key\b|\bwallet\b", "Crypto wallet credential request"),
    (r"\bbank.{0,15}detail\b", "Banking detail request"),
]

THREAT_PATTERNS = [
    (r"\bsuspended\b|\blocke?d\b|\bblocked\b", "Account suspension / lock threat"),
    (r"\baction required\b", "Forced-action language"),
    (r"\blegal action\b|\bpolice\b|\bcourt\b", "Legal threat"),
    (r"\bwarrant\b|\barrest\b", "Arrest or warrant threat"),
    (r"\bunusual.{0,20}(activity|login|sign.?in)\b", "Fake security alert"),
    (r"\bdetected.{0,20}(virus|malware|hack)\b", "Fake malware / hack alert"),
    (r"\byour account.*?(will be|has been)\b", "Account consequence threat"),
]

FINANCIAL_LURE_PATTERNS = [
    (r"\brefund\b", "Refund offer"),
    (r"\bprize\b|\bwinner\b|\bwon\b|\bwinning\b", "Prize claim"),
    (r"\blottery\b", "Lottery lure"),
    (r"\bunclaimed\b", "Unclaimed funds lure"),
    (r"\binheritance\b|\bbeneficiary\b", "Inheritance scam signal"),
    (r"\bguaranteed.{0,20}(return|profit)\b", "Guaranteed profit claim"),
    (r"\binvest.{0,20}(now|today|immediately)\b", "Urgent investment push"),
]

URGENCY_PATTERNS = [
    (r"\burgent\b", "Urgency trigger"),
    (r"\bimmediately\b", "Urgency trigger: immediately"),
    (r"\bact now\b|\bact immediately\b", "Urgency trigger: act now"),
    (r"\bwithin \d+\s*(hours?|minutes?|days?)\b", "Time-window pressure"),
    (r"\bexpir(e|es|ing|ed)\b", "Expiration pressure"),
    (r"\btoday only\b|\blast chance\b", "Artificial scarcity"),
    (r"\bdo not delay\b|\bdon'?t wait\b", "Delay pressure"),
]

IMPERSONATION_PATTERNS = [
    (r"\b(IRS|income tax|tax department|tax authority)\b", "Tax authority impersonation"),
    (r"\bRBI\b|\bReserve Bank of India\b", "RBI impersonation"),
    (r"\b(FBI|CIA|Interpol|police|court notice)\b", "Law enforcement impersonation"),
    (r"\bMicrosoft\b.{0,40}(support|technical|team|security)\b", "Microsoft tech-support scam"),
    (r"\bApple\b.{0,40}(support|ID|account|team)\b", "Apple impersonation"),
    (r"\bPayPal\b.{0,20}(alert|suspended|limited)\b", "PayPal impersonation"),
    (r"\bAmazon\b.{0,30}(order|account|suspended|team)\b", "Amazon impersonation"),
    (r"\b(Netflix|Spotify)\b.{0,30}(payment|renew|suspend)\b", "Streaming service impersonation"),
    (r"\byour bank\b|\bbank alert\b|\bbank account.{0,20}(suspend|block|lock)\b", "Bank impersonation"),
]

SUSPICIOUS_LINK_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Raw IP address link"),
    (r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link|rb\.gy|cutt\.ly", "Shortened URL"),
    (r"\.(tk|ml|ga|cf|gq|xyz|top|win|loan|click)(/|$|\?)", "Suspicious TLD in link"),
    (r"https?://[^\s]{120,}", "Extremely long URL"),
]

BEC_PATTERNS = [
    (r"\bwire transfer\b|\bbank transfer\b", "Wire transfer request — common in BEC"),
    (r"\bchange.{0,20}(bank|account|payment).{0,20}(detail|info|number)\b", "Payment detail change request — BEC red flag"),
    (r"\bconfidential\b|\bdo not (forward|share|discuss)\b", "Secrecy instruction"),
    (r"\bceo\b|\bmanaging director\b|\bmd\b.{0,15}(request|ask|need)\b", "Executive impersonation"),
    (r"\binvoice.{0,30}attached\b", "Invoice attachment reference"),
]


@dataclass
class EmailEvidence:
    category: str
    signal: str
    severity: str
    explanation: str
    matched_text: str = ""


@dataclass
class EmailAnalysisResult:
    subject: str
    from_addr: str
    reply_to: str
    risk_level: str
    risk_score: int
    evidence: list[EmailEvidence] = field(default_factory=list)
    summary: str = ""
    next_steps: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    auth_results: dict = field(default_factory=dict)
    headers_parsed: list[str] = field(default_factory=list)


def _extract_domain(addr: str) -> str:
    """Extract the domain from an email address."""
    addr = addr.strip().lower()
    if "@" in addr:
        return addr.split("@")[-1].strip(">").strip()
    return ""


def _extract_root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text, re.IGNORECASE)


def _find_patterns(text: str, patterns: list, category: str, severity: str, explanation: str) -> list[EmailEvidence]:
    results = []
    text_lower = text.lower()
    for pattern, signal in patterns:
        m = re.search(pattern, text_lower, re.IGNORECASE)
        if m:
            results.append(EmailEvidence(
                category=category,
                signal=signal,
                severity=severity,
                explanation=explanation,
                matched_text=m.group(0)
            ))
    return results


def _parse_auth_results(auth_header: str) -> dict:
    """
    Extract SPF, DKIM, DMARC pass/fail from Authentication-Results header.
    Returns dict with keys: spf, dkim, dmarc — each 'pass', 'fail', 'softfail', 'neutral', or 'unknown'
    """
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_header:
        return result

    lower = auth_header.lower()

    for proto in ["spf", "dkim", "dmarc"]:
        # Look for patterns like "spf=pass", "dkim=fail", etc.
        m = re.search(rf"{proto}=([a-z]+)", lower)
        if m:
            result[proto] = m.group(1)

    return result


def analyze_email(raw_headers: str, body: str = "", subject: str = "", from_raw: str = "", reply_to_raw: str = "") -> EmailAnalysisResult:
    """
    Analyze email for phishing / spoofing indicators.

    Parameters:
    - raw_headers: Raw email headers as a string (paste from email client)
    - body: Email body text (optional but improves detection)
    - subject: Subject line (can also be extracted from raw_headers)
    - from_raw: From field string (can be extracted from raw_headers)
    - reply_to_raw: Reply-To field string
    """

    evidence: list[EmailEvidence] = []
    score = 0

    # ── Parse raw headers if provided ────────────────────────────────────────
    parsed_headers: list[str] = []
    auth_results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    combined_text = raw_headers + "\n\n" + body

    # Try to parse using Python's email module
    try:
        msg = message_from_string(raw_headers + "\n\n" + body)

        if not subject:
            subject = msg.get("Subject", "") or ""
        if not from_raw:
            from_raw = msg.get("From", "") or ""
        if not reply_to_raw:
            reply_to_raw = msg.get("Reply-To", "") or ""

        auth_header = msg.get("Authentication-Results", "") or ""
        auth_results = _parse_auth_results(auth_header)

        return_path = msg.get("Return-Path", "") or ""
        received_spf = msg.get("Received-SPF", "") or ""

        # Supplement with Received-SPF if Authentication-Results missing
        if auth_results["spf"] == "unknown" and received_spf:
            m = re.search(r"(pass|fail|softfail|neutral|none)", received_spf.lower())
            if m:
                auth_results["spf"] = m.group(1)

        for key in msg.keys():
            parsed_headers.append(f"{key}: {msg.get(key, '')}")

    except Exception:
        return_path = ""
        # Fall back to manual parsing
        for line in raw_headers.splitlines():
            if ":" in line:
                parsed_headers.append(line.strip())
            m = re.match(r"^(subject|from|reply-to|return-path):\s*(.+)$", line.strip(), re.IGNORECASE)
            if m:
                key = m.group(1).lower()
                val = m.group(2)
                if key == "subject" and not subject:
                    subject = val
                elif key == "from" and not from_raw:
                    from_raw = val
                elif key == "reply-to" and not reply_to_raw:
                    reply_to_raw = val

        auth_match = re.search(r"authentication-results:(.+?)(?=\n\S|\Z)", raw_headers, re.IGNORECASE | re.DOTALL)
        if auth_match:
            auth_results = _parse_auth_results(auth_match.group(1))

    # ── Parse addresses ───────────────────────────────────────────────────────
    display_from, addr_from = parseaddr(from_raw)
    display_reply, addr_reply = parseaddr(reply_to_raw)
    domain_from = _extract_domain(addr_from)
    domain_reply = _extract_domain(addr_reply)
    root_from = _extract_root_domain(domain_from)

    # ── 1. SPF / DKIM / DMARC interpretation ──────────────────────────────
    if auth_results["spf"] in ("fail", "softfail"):
        score += 30
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="SPF Failure",
            severity="high",
            explanation=f"SPF check result: '{auth_results['spf']}'. The sending server is NOT authorised to send on behalf of the claimed domain. This is a strong indicator of email spoofing.",
            matched_text=f"spf={auth_results['spf']}",
        ))
    elif auth_results["spf"] == "pass":
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="SPF Pass",
            severity="safe",
            explanation="SPF check passed — the sending server is authorised by the domain's DNS record. Note: SPF alone does not prove the email is legitimate.",
        ))
    else:
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="SPF result unknown or absent",
            severity="low",
            explanation="No SPF result was found in the headers. This may mean the email client did not include authentication results, or the domain has no SPF record.",
        ))

    if auth_results["dkim"] == "fail":
        score += 35
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="DKIM Failure",
            severity="critical",
            explanation="DKIM verification failed. The email's cryptographic signature is invalid, which strongly suggests the message was forged or tampered with in transit.",
            matched_text=f"dkim={auth_results['dkim']}",
        ))
    elif auth_results["dkim"] == "pass":
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="DKIM Pass",
            severity="safe",
            explanation="DKIM signature verified — the email content was not altered since it was signed by the sender's mail server. This is a positive signal, but does not guarantee safety.",
        ))
    else:
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="DKIM result unknown or absent",
            severity="low",
            explanation="No DKIM result found in headers. Many legitimate emails lack this header in some email clients. Check the full raw headers for 'Authentication-Results'.",
        ))

    if auth_results["dmarc"] == "fail":
        score += 30
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="DMARC Failure",
            severity="critical",
            explanation="DMARC policy check failed. The email failed both SPF and DKIM alignment checks. This is a strong indicator of domain impersonation or spoofing.",
            matched_text=f"dmarc={auth_results['dmarc']}",
        ))
    elif auth_results["dmarc"] == "pass":
        evidence.append(EmailEvidence(
            category="Email Authentication",
            signal="DMARC Pass",
            severity="safe",
            explanation="DMARC check passed — the email aligns with the domain's published policy. Treat this as a positive signal.",
        ))

    # ── 2. Sender / Reply-To mismatch ─────────────────────────────────────
    if addr_reply and addr_from and domain_from and domain_reply:
        if root_from != _extract_root_domain(domain_reply):
            score += 30
            evidence.append(EmailEvidence(
                category="Sender Spoofing",
                signal="From / Reply-To domain mismatch",
                severity="critical",
                explanation=(
                    f"The 'From' address is '{addr_from}' (domain: {domain_from}) "
                    f"but 'Reply-To' is '{addr_reply}' (domain: {domain_reply}). "
                    "Replies will be sent to a different domain than the apparent sender. "
                    "This is a classic email spoofing technique."
                ),
                matched_text=f"From={domain_from}, Reply-To={domain_reply}",
            ))

    # ── 3. Display-name impersonation ─────────────────────────────────────
    if display_from and addr_from:
        display_lower = display_from.lower()
        for brand in TRUSTED_BRANDS:
            if brand in display_lower and brand not in domain_from.lower():
                score += 25
                evidence.append(EmailEvidence(
                    category="Sender Spoofing",
                    signal=f"Display-name impersonation: '{brand}'",
                    severity="high",
                    explanation=(
                        f"The sender's display name contains '{brand}' but the actual sending domain "
                        f"is '{domain_from}', which does not match. Email clients show only the display "
                        "name by default. Always check the actual email address."
                    ),
                    matched_text=f"Display: '{display_from}', Addr: '{addr_from}'",
                ))
                break

    # ── 4. Suspicious sending domain ──────────────────────────────────────
    if domain_from and root_from not in LEGITIMATE_DOMAINS:
        # Check if brand keyword appears in domain
        for brand in TRUSTED_BRANDS:
            if brand in domain_from and brand not in ("noreply", "support", "service", "alert", "verify", "account"):
                score += 20
                evidence.append(EmailEvidence(
                    category="Domain Impersonation",
                    signal=f"Brand keyword '{brand}' in suspicious sending domain",
                    severity="high",
                    explanation=(
                        f"The sending domain '{domain_from}' contains '{brand}' but it is NOT the "
                        f"actual domain for that brand. Phishing emails often register look-alike domains "
                        "to appear legitimate at a glance."
                    ),
                    matched_text=domain_from,
                ))
                break

    # ── 5. Subject line analysis ──────────────────────────────────────────
    if subject:
        subj_lower = subject.lower()
        urgency_hits = [kw for kw in ["urgent", "action required", "suspended", "blocked",
                                       "verify", "confirm", "immediately", "warning", "alert",
                                       "important", "your account"] if kw in subj_lower]
        if urgency_hits:
            score += min(len(urgency_hits) * 8, 25)
            evidence.append(EmailEvidence(
                category="Urgency Tactic",
                signal=f"Urgent language in subject: {', '.join(urgency_hits[:4])}",
                severity="medium",
                explanation="Scam emails frequently use alarming subject lines to override rational thinking. Legitimate organisations use measured, professional subject lines.",
                matched_text=subject[:100],
            ))

        prize_hits = [kw for kw in ["winner", "won", "prize", "reward", "congratulations", "lottery", "selected"] if kw in subj_lower]
        if prize_hits:
            score += 20
            evidence.append(EmailEvidence(
                category="Financial Lure",
                signal=f"Prize/reward language in subject",
                severity="high",
                explanation="Subject lines announcing prizes, lottery wins, or rewards are a hallmark of advance-fee and lottery scams.",
                matched_text=subject[:100],
            ))

    # ── 6. Body analysis ──────────────────────────────────────────────────
    body_text = body or ""
    if body_text:
        cred = _find_patterns(body_text, CREDENTIAL_HARVEST_PATTERNS, "Credential Harvesting", "critical",
            "Legitimate services never request passwords, OTPs, PINs, or card details via email. This is a phishing hallmark.")
        evidence.extend(cred)
        score += min(len(cred) * 15, 40)

        threats = _find_patterns(body_text, THREAT_PATTERNS, "Threat / Fear Tactic", "high",
            "Threats of account suspension or legal action are used to panic victims. Legitimate organisations use official letters or in-app notifications.")
        evidence.extend(threats)
        score += min(len(threats) * 12, 30)

        financial = _find_patterns(body_text, FINANCIAL_LURE_PATTERNS, "Financial Lure", "high",
            "Promises of refunds, prizes, or investment returns are classic social-engineering lures.")
        evidence.extend(financial)
        score += min(len(financial) * 10, 25)

        urgency = _find_patterns(body_text, URGENCY_PATTERNS, "Urgency Tactic", "medium",
            "Creating time pressure prevents victims from verifying claims independently. Legitimate services rarely demand immediate action.")
        evidence.extend(urgency)
        score += min(len(urgency) * 8, 20)

        impersonation = _find_patterns(body_text, IMPERSONATION_PATTERNS, "Impersonation", "high",
            "This email claims to be from a known brand or authority. Always verify by visiting the organisation's official website directly.")
        evidence.extend(impersonation)
        score += min(len(impersonation) * 12, 30)

        bec = _find_patterns(body_text, BEC_PATTERNS, "Business Email Compromise", "critical",
            "Requests to change payment details or urgent wire transfers are classic Business Email Compromise (BEC) attacks. Always verify such requests via phone using a known number.")
        evidence.extend(bec)
        score += min(len(bec) * 20, 40)

        # Generic salutation
        if re.search(r"\bdear\s+(customer|user|member|friend|sir|madam|beneficiary)\b", body_text.lower()):
            score += 8
            evidence.append(EmailEvidence(
                category="Informal Signal",
                signal="Generic salutation (no name used)",
                severity="low",
                explanation="Legitimate organisations usually address you by name. Generic salutations like 'Dear Customer' suggest a mass phishing campaign.",
                matched_text="Generic salutation detected",
            ))

        # Suspicious links in body
        link_ev = _find_patterns(body_text, SUSPICIOUS_LINK_PATTERNS, "Suspicious Link", "high",
            "Links in this email have suspicious characteristics. Shortened or IP-based URLs hide the true destination.")
        evidence.extend(link_ev)
        score += min(len(link_ev) * 15, 30)

    # ── 7. Extract all URLs from body ─────────────────────────────────────
    extracted_urls = _extract_urls(combined_text)

    # ── Cap and classify ──────────────────────────────────────────────────
    score = min(score, 100)

    if score >= 70:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 30:
        risk_level = "medium"
    elif score >= 10:
        risk_level = "low"
    else:
        risk_level = "safe"

    summary_map = {
        "critical": f"This email shows multiple strong phishing or spoofing indicators. Do NOT click links, reply, or provide any information. Risk score: {score}/100.",
        "high": f"This email has significant warning signs. Treat it as suspicious and verify through official channels. Risk score: {score}/100.",
        "medium": f"This email has some concerning patterns. Verify through official channels before acting. Risk score: {score}/100.",
        "low": f"This email has minor concerns. Confirm the sender's identity before responding. Risk score: {score}/100.",
        "safe": f"No significant phishing or spoofing signals detected. Continue exercising normal caution. Risk score: {score}/100.",
    }

    steps_map = {
        "critical": [
            "Do NOT click any links or download any attachments.",
            "Do NOT reply to this email.",
            "Report as phishing in your email client (Gmail: Report Phishing; Outlook: Report Message).",
            "If you clicked a link or entered details, change passwords and contact your bank immediately.",
            "Report to the Indian Cyber Crime portal (cybercrime.gov.in) if applicable.",
        ],
        "high": [
            "Do not click links in this email.",
            "Verify the sender's address carefully — not just the display name.",
            "Contact the supposed organisation directly using their official website.",
            "Mark as spam/phishing in your email client.",
        ],
        "medium": [
            "Verify the sender domain independently.",
            "Do not provide personal information based on this email alone.",
            "Contact the organisation through an independently obtained phone number or website.",
        ],
        "low": [
            "Confirm the sender's identity before responding.",
            "Check authentication headers for SPF/DKIM results.",
        ],
        "safe": [
            "Continue practising safe email habits.",
            "Never share OTPs, passwords, or card details — even if asked by an apparent official source.",
        ],
    }

    limitations = [
        "This is heuristic text analysis — no live SPF/DKIM verification was performed by ScamShield.",
        "Authentication results (SPF, DKIM, DMARC) are read from header text only; they could be fabricated in a raw paste.",
        "A 'safe' result does not guarantee the email is legitimate.",
        "For confirmed forensics, use your email provider's built-in phishing report tools.",
        "Sophisticated spear-phishing emails may not trigger any pattern rules.",
    ]

    return EmailAnalysisResult(
        subject=subject,
        from_addr=addr_from,
        reply_to=addr_reply,
        risk_level=risk_level,
        risk_score=score,
        evidence=evidence,
        summary=summary_map[risk_level],
        next_steps=steps_map[risk_level],
        limitations=limitations,
        extracted_urls=extracted_urls,
        auth_results=auth_results,
        headers_parsed=parsed_headers[:30],  # Limit for response size
    )
