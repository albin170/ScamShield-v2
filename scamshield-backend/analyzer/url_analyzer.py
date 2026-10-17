"""
URL Analyzer — Static analysis of URLs for scam/phishing indicators.
No automatic URL fetching to avoid SSRF risks.
"""
import re
import math
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field
from typing import Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from analyzer.advanced_checks import (
    check_typosquatting, check_homograph, check_url_shortener,
    check_fresh_domain_pattern, check_data_uri, AdvancedSignal,
)

# ---------------------------------------------------------------------------
# Known brand / impersonation targets
# ---------------------------------------------------------------------------
BRAND_KEYWORDS = [
    "paypal", "amazon", "netflix", "apple", "google", "microsoft", "facebook",
    "instagram", "whatsapp", "twitter", "ebay", "walmart", "chase", "bankofamerica",
    "wellsfargo", "citibank", "hsbc", "irs", "gov", "fedex", "ups", "dhl",
    "linkedin", "dropbox", "zoom", "youtube", "spotify", "tiktok", "binance",
    "coinbase", "crypto", "blockchain", "metamask", "upi", "paytm", "phonepe",
    "sbi", "hdfc", "icici", "axis", "rbi", "telegram", "discord", "steam",
    "openai", "chatgpt", "gemini", "roblox", "epicgames", "airdrop",
]

# Free / disposable TLDs commonly abused
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom free TLDs
    ".xyz", ".top", ".win", ".loan", ".club", ".online",
    ".site", ".store", ".info", ".biz", ".work", ".click",
    ".vip", ".monster", ".quest", ".rest", ".cam", ".bar",
}

SAFE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co.uk", ".in", ".dev", ".ai"}

# Legitimate well-known domains (not exhaustive; used for exact-match check)
LEGITIMATE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "linkedin.com", "github.com", "wikipedia.org", "reddit.com",
    "whatsapp.com", "zoom.us", "dropbox.com", "spotify.com", "ebay.com",
    "telegram.org", "discord.com", "openai.com", "steamcommunity.com",
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "limited time", "expire", "suspended",
    "verify", "confirm", "click here", "winner", "congratulations", "free",
    "prize", "reward", "bonus", "exclusive", "login", "password", "account",
    "blocked", "unusual activity", "security alert", "update", "required",
]


@dataclass
class URLEvidence:
    signal: str
    severity: str  # "high" | "medium" | "low" | "safe"
    explanation: str


@dataclass
class URLAnalysisResult:
    url: str
    risk_level: str        # "safe" | "low" | "medium" | "high" | "critical"
    risk_score: int        # 0-100
    evidence: list[URLEvidence] = field(default_factory=list)
    summary: str = ""
    next_steps: list[str] = field(default_factory=list)
    is_https: bool = False
    domain: str = ""
    has_ip_host: bool = False
    redirect_chain_depth: int = 0
    limitations: list[str] = field(default_factory=list)


def _entropy(text: str) -> float:
    """Shannon entropy — high entropy in subdomains suggests randomness."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_root_domain(hostname: str) -> str:
    """Naive root-domain extractor (avoids tldextract dependency at import time)."""
    parts = hostname.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


def analyze_url(url: str) -> URLAnalysisResult:
    raw_url = url.strip()

    # Ensure scheme for parsing
    if not raw_url.startswith(("http://", "https://")):
        parse_target = "http://" + raw_url
    else:
        parse_target = raw_url

    try:
        parsed = urlparse(parse_target)
    except Exception:
        return URLAnalysisResult(
            url=raw_url,
            risk_level="high",
            risk_score=80,
            summary="Could not parse the URL — it may be malformed.",
            evidence=[URLEvidence("Malformed URL", "high", "The URL could not be parsed. Legitimate URLs follow standard formatting.")],
            next_steps=["Do not click this link.", "Report it to your IT department or the platform where you received it."],
        )

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_path = path + ("?" + query if query else "")
    root_domain = _extract_root_domain(hostname)
    is_https = raw_url.startswith("https://")

    evidence: list[URLEvidence] = []
    score = 0

    # ── 1. HTTPS check ──────────────────────────────────────────────────────
    if not is_https:
        score += 20
        evidence.append(URLEvidence(
            "No HTTPS encryption",
            "high",
            "The URL uses HTTP, not HTTPS. Your data (passwords, form inputs) can be intercepted by anyone on the same network."
        ))
    else:
        evidence.append(URLEvidence(
            "HTTPS present",
            "safe",
            "The connection is encrypted. Note: HTTPS does not guarantee the site is legitimate — scammers also use HTTPS."
        ))

    # ── 2. IP address as host ────────────────────────────────────────────────
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip = bool(ip_pattern.match(hostname))
    if has_ip:
        score += 35
        evidence.append(URLEvidence(
            "IP address used instead of domain",
            "high",
            f"The host is a raw IP ({hostname}) rather than a registered domain name. Legitimate services almost never do this."
        ))

    # ── 3. Brand impersonation check ────────────────────────────────────────
    impersonated_brands = []
    for brand in BRAND_KEYWORDS:
        if brand in hostname and root_domain not in LEGITIMATE_DOMAINS:
            impersonated_brands.append(brand)
    if impersonated_brands:
        score += 40
        brands_str = ", ".join(impersonated_brands[:3])
        evidence.append(URLEvidence(
            f"Brand impersonation detected: {brands_str}",
            "critical",
            f"The domain contains '{brands_str}' but is NOT the real website. "
            f"For example, 'paypal-login.com' is NOT paypal.com. "
            f"Real domain: {root_domain}."
        ))

    # ── 4. Suspicious TLD ───────────────────────────────────────────────────
    tld = "." + root_domain.split(".")[-1] if "." in root_domain else ""
    if tld and tld in SUSPICIOUS_TLDS:
        score += 20
        evidence.append(URLEvidence(
            f"Suspicious top-level domain: {tld}",
            "medium",
            f"The TLD '{tld}' is frequently used for free or low-cost domain registrations popular among scammers. Legitimate businesses rarely use {tld}."
        ))

    # ── 5. Excessive subdomains / long domain ───────────────────────────────
    subdomain_parts = hostname.split(".")[:-2]
    if len(subdomain_parts) >= 3:
        score += 15
        evidence.append(URLEvidence(
            f"Deeply nested subdomains ({len(subdomain_parts)} levels)",
            "medium",
            f"The URL has {len(subdomain_parts)} subdomain levels (e.g., 'verify.secure.login.example.com'). "
            "Legitimate sites rarely need more than one or two subdomain levels."
        ))
    elif len(subdomain_parts) == 2 and subdomain_parts[0] not in ("www", "mail", "shop", "app", "api", "m"):
        score += 8
        evidence.append(URLEvidence(
            "Unusual subdomain pattern",
            "low",
            f"The subdomain '{'.'.join(subdomain_parts)}' is uncommon. Be cautious."
        ))

    # ── 6. Domain entropy (random-looking domains) ───────────────────────────
    domain_label = root_domain.split(".")[0] if "." in root_domain else root_domain
    ent = _entropy(domain_label)
    if ent > 3.8 and len(domain_label) > 8:
        score += 15
        evidence.append(URLEvidence(
            "Random-looking domain name",
            "medium",
            f"The domain '{root_domain}' appears randomly generated (high character entropy). "
            "Phishing kits often use auto-generated domains to avoid blocklists."
        ))

    # ── 7. URL length ────────────────────────────────────────────────────────
    url_len = len(raw_url)
    if url_len > 200:
        score += 15
        evidence.append(URLEvidence(
            f"Extremely long URL ({url_len} characters)",
            "medium",
            "Very long URLs often hide the true destination by burying the malicious domain among legitimate-looking text."
        ))
    elif url_len > 100:
        score += 7
        evidence.append(URLEvidence(
            f"Long URL ({url_len} characters)",
            "low",
            "Somewhat long URL. Check the domain portion carefully."
        ))

    # ── 8. Suspicious path keywords ─────────────────────────────────────────
    path_lower = full_path.lower()
    path_hits = [kw for kw in ["login", "verify", "account", "update", "confirm", "secure", "password", "credential", "signin", "auth", "wallet", "bank"] if kw in path_lower]
    if path_hits:
        score += min(len(path_hits) * 8, 25)
        evidence.append(URLEvidence(
            f"Credential-related path keywords: {', '.join(path_hits[:4])}",
            "medium",
            "The URL path contains words like 'login', 'verify', or 'password'. "
            "Phishing pages often include these terms to appear legitimate while harvesting credentials."
        ))

    # ── 9. Redirect / tracking signals ──────────────────────────────────────
    qs = parse_qs(query)
    redirect_params = [p for p in qs if p.lower() in ("url", "redirect", "goto", "next", "return", "redir", "link", "target")]
    if redirect_params:
        score += 12
        evidence.append(URLEvidence(
            f"Open-redirect parameters: {', '.join(redirect_params)}",
            "medium",
            "Query parameters like '?url=' or '?redirect=' may chain you through to a different, possibly malicious, destination."
        ))

    shortener_sigs = check_url_shortener(hostname)
    for sig in shortener_sigs:
        score += 15
        evidence.append(URLEvidence(
            sig.check,
            sig.severity,
            sig.explanation,
        ))

    homograph_sigs = check_homograph(hostname)
    for sig in homograph_sigs:
        score += 35
        evidence.append(URLEvidence(
            sig.check,
            sig.severity,
            f"{sig.explanation} (Detail: {sig.detail})",
        ))

    typo_sigs = check_typosquatting(domain_label)
    for sig in typo_sigs:
        score += 30 if sig.severity == "critical" else 20
        evidence.append(URLEvidence(
            sig.check,
            sig.severity,
            f"{sig.explanation} (Detail: {sig.detail})",
        ))

    fresh_sigs = check_fresh_domain_pattern(domain_label)
    for sig in fresh_sigs:
        score += 15
        evidence.append(URLEvidence(
            sig.check,
            sig.severity,
            sig.explanation,
        ))

    # ── 10. Data URI or javascript: scheme ──────────────────────────────────
    if raw_url.lower().startswith(("javascript:", "data:")):
        score += 50
        evidence.append(URLEvidence(
            "Dangerous URL scheme",
            "critical",
            "URLs starting with 'javascript:' or 'data:' are used to execute arbitrary code in your browser. Never click these."
        ))

    # ── 11. Legitimate domain whitelist bonus ────────────────────────────────
    if root_domain in LEGITIMATE_DOMAINS:
        score = max(0, score - 30)
        evidence.append(URLEvidence(
            "Recognised legitimate domain",
            "safe",
            f"'{root_domain}' is a well-known, established domain. Verify the full URL still looks correct."
        ))

    # ── Urgency keywords in URL ──────────────────────────────────────────────
    url_lower = raw_url.lower()
    urgency_hits = [kw for kw in ["urgent", "free", "winner", "prize", "claim", "expire", "suspend", "blocked", "verify"] if kw in url_lower]
    if urgency_hits:
        score += min(len(urgency_hits) * 6, 18)
        evidence.append(URLEvidence(
            f"Urgency/reward language in URL: {', '.join(urgency_hits[:4])}",
            "low",
            "Words like 'urgent', 'winner', or 'free' embedded in URLs are classic social-engineering triggers."
        ))

    # ── Cap score ────────────────────────────────────────────────────────────
    score = min(score, 100)

    # ── Risk level ───────────────────────────────────────────────────────────
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

    # ── Summary ──────────────────────────────────────────────────────────────
    summary_map = {
        "critical": f"This URL shows multiple serious red flags. Do NOT visit it. Risk score: {score}/100.",
        "high": f"This URL has significant warning signs. Avoid interacting with it. Risk score: {score}/100.",
        "medium": f"This URL has some suspicious characteristics. Proceed with caution. Risk score: {score}/100.",
        "low": f"This URL has minor concerns. Double-check before proceeding. Risk score: {score}/100.",
        "safe": f"No significant red flags detected. Still exercise normal caution online. Risk score: {score}/100.",
    }

    # ── Next steps ───────────────────────────────────────────────────────────
    steps_map = {
        "critical": [
            "Do NOT click this link.",
            "Block the sender immediately.",
            "Report to the platform (email provider, SMS carrier, social media).",
            "If you already clicked, change your passwords and enable 2FA.",
            "Report to your national cybercrime portal.",
        ],
        "high": [
            "Avoid clicking this link.",
            "Verify the sender through an independent channel.",
            "Search the official website directly via a search engine instead.",
            "Report the message/link to the platform.",
        ],
        "medium": [
            "Be cautious before clicking.",
            "Hover over the link to verify the destination.",
            "Go directly to the official website rather than clicking.",
            "If you must visit, use a private/incognito browser.",
        ],
        "low": [
            "Check that the domain matches the expected service.",
            "Look for the padlock icon and verify the certificate.",
            "If entering sensitive data, confirm you are on the right site.",
        ],
        "safe": [
            "Always verify the site certificate (padlock icon).",
            "Never enter passwords on sites you reached via an unsolicited link.",
        ],
    }

    limitations = [
        "This is static analysis — the URL was NOT fetched or opened.",
        "Sophisticated phishing sites can use HTTPS and legitimate-looking domains.",
        "A 'safe' rating here does not guarantee the site is safe.",
        "Check real-time threat databases (VirusTotal, Google Safe Browsing) for additional verification.",
    ]

    return URLAnalysisResult(
        url=raw_url,
        risk_level=risk_level,
        risk_score=score,
        evidence=evidence,
        summary=summary_map[risk_level],
        next_steps=steps_map[risk_level],
        is_https=is_https,
        domain=root_domain,
        has_ip_host=has_ip,
        limitations=limitations,
    )
