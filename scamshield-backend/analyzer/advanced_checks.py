"""
Advanced detection modules for ScamShield.
Includes:
  - Typosquatting / Levenshtein distance detection
  - Homograph / IDN (Punycode) attack detection
  - Domain-age heuristic signals
  - Redirect-chain / shortened-URL detection
  - Threat-category scoring for radar chart
"""
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Levenshtein distance (pure Python, no deps)
# ---------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


# Well-known brand domain roots to compare against
BRAND_DOMAINS = [
    "paypal", "amazon", "netflix", "apple", "google", "microsoft", "facebook",
    "instagram", "snapchat", "whatsapp", "twitter", "ebay", "walmart", "chase", "bankofamerica",
    "wellsfargo", "citibank", "hsbc", "linkedin", "dropbox", "zoom", "youtube",
    "spotify", "tiktok", "binance", "coinbase", "metamask", "paytm", "phonepe",
    "sbi", "hdfc", "icici", "axis", "airtel", "jiomart", "flipkart", "myntra",
    "telegram", "discord", "steam", "openai", "chatgpt", "gemini", "roblox",
]

# IDN/Homograph lookalike map — unicode chars that look like ASCII
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
    'ɑ': 'a', 'ɡ': 'g', 'ⅼ': 'l', 'ƅ': 'b',                        # IPA lookalikes
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',   # Numeric subs
    '@': 'a', '$': 's',
}

# Generic third-party URL shorteners (hiding destination)
GENERIC_SHORTENERS = {
    "bit.ly", "tinyurl.com", "ow.ly", "short.link",
    "rb.gy", "cutt.ly", "is.gd", "tiny.cc", "buff.ly", "adf.ly",
    "bc.vc", "forms.gle",
}

# Official brand shorteners
OFFICIAL_SHORTENERS = {
    "youtu.be", "ig.me", "wa.me", "fb.me", "m.me", "t.co", "amzn.to", "spoti.fi", "t.me", "discord.gg", "git.io", "lnkd.in"
}

SHORTENED_DOMAINS = GENERIC_SHORTENERS.union(OFFICIAL_SHORTENERS)

# Suspicious patterns in fresh/throwaway domains
FRESH_DOMAIN_SIGNALS = [
    r"\d{4,}",            # Long number sequences (auto-generated)
    r"-[a-z]{2,4}-",      # Multiple short words joined by dashes
    r"[a-z]{20,}",        # Very long random-looking label
    r"(secure|verify|login|update|confirm|bank|pay|account|support){2,}",  # Keyword stacking
]


@dataclass
class AdvancedSignal:
    check: str
    severity: str
    explanation: str
    detail: str = ""


def check_typosquatting(domain_label: str, hostname: str = "") -> list[AdvancedSignal]:
    """
    Compare the SLD (second-level domain) against known brand names.
    Flag if edit-distance <= 2 but not an exact match.
    Excludes verified official domains and brand shorteners (e.g. youtu.be).
    """
    signals = []
    label = domain_label.lower().strip()
    host = hostname.lower().strip()

    # Never flag official brand shorteners or sub-labels
    if host in OFFICIAL_SHORTENERS or label in {"youtu", "snap", "ig", "fb", "wa"}:
        return []

    for brand in BRAND_DOMAINS:
        if label == brand:
            continue  # Exact match — not typosquatting (handled by whitelist)
        dist = levenshtein(label, brand)
        if dist == 1:
            signals.append(AdvancedSignal(
                check="Typosquatting (1-char edit)",
                severity="critical",
                explanation=(
                    f"The domain '{label}' is 1 character away from '{brand}'. "
                    f"This is a classic typosquatting technique where attackers register "
                    f"misspelled versions of trusted brands to trap users who mistype URLs."
                ),
                detail=f"'{label}' -> '{brand}' (distance=1)",
            ))
        elif dist == 2 and len(label) >= 5 and label not in ("youtube", "whatsapp", "google"):
            signals.append(AdvancedSignal(
                check="Possible typosquatting (2-char edit)",
                severity="high",
                explanation=(
                    f"The domain '{label}' closely resembles '{brand}' (2-character difference). "
                    f"Verify you have the correct domain before entering any credentials."
                ),
                detail=f"'{label}' -> '{brand}' (distance=2)",
            ))
    return signals


def check_homograph(hostname: str) -> list[AdvancedSignal]:
    """
    Detect IDN homograph attacks and numeric character substitutions.
    Punycoded domains (xn--...) are also flagged.
    """
    signals = []

    # 1. Punycode / xn-- prefix signals IDN encoding
    if "xn--" in hostname.lower():
        signals.append(AdvancedSignal(
            check="IDN / Punycode encoding detected",
            severity="critical",
            explanation=(
                "This domain uses Internationalized Domain Name (IDN) encoding (xn-- prefix). "
                "Attackers register domains using lookalike Unicode characters (e.g., Cyrillic 'а' "
                "instead of Latin 'a') that appear identical in your browser's address bar. "
                "Always inspect the raw punycode if you see xn-- in a link."
            ),
            detail=hostname,
        ))
        return signals  # Punycode is the strongest signal; don't double-count

    # 2. Detect unicode homograph characters
    suspicious_chars = []
    for ch in hostname:
        if ch in HOMOGRAPH_MAP and ch not in ".-_0123456789abcdefghijklmnopqrstuvwxyz":
            suspicious_chars.append(ch)

    if suspicious_chars:
        signals.append(AdvancedSignal(
            check="Homograph / lookalike characters",
            severity="critical",
            explanation=(
                f"The hostname contains characters ({', '.join(repr(c) for c in suspicious_chars)}) "
                "that look like standard letters but are different Unicode code points. "
                "This is an IDN homograph attack — the domain is designed to visually impersonate a trusted site."
            ),
            detail=f"Suspect chars: {suspicious_chars}",
        ))

    # 3. Mixed script detection (Latin + Cyrillic in same label)
    scripts = set()
    for ch in hostname.replace(".", "").replace("-", ""):
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
    if len(scripts) > 1:
        signals.append(AdvancedSignal(
            check="Mixed script domain",
            severity="critical",
            explanation=(
                f"The domain mixes multiple Unicode scripts ({', '.join(scripts)}). "
                "Legitimate domains use a single script. Mixed scripts are a hallmark of "
                "sophisticated homograph phishing attacks."
            ),
        ))

    # 4. Numeric substitutions in brand-looking contexts (e.g., amaz0n, g00gle)
    normalized = hostname
    for ch, replacement in HOMOGRAPH_MAP.items():
        normalized = normalized.replace(ch, replacement)
    if normalized != hostname:
        for brand in BRAND_DOMAINS:
            if brand in normalized and brand not in hostname:
                signals.append(AdvancedSignal(
                    check=f"Numeric character substitution impersonating '{brand}'",
                    severity="high",
                    explanation=(
                        f"The domain uses number/symbol substitutions (e.g., '0' for 'o', '3' for 'e') "
                        f"to mimic '{brand}'. The real domain is '{brand}.com'. This technique is "
                        "used to bypass simple keyword filters."
                    ),
                    detail=f"Original: {hostname}, Normalized: {normalized}",
                ))
                break

    return signals


def check_url_shortener(root_domain: str) -> list[AdvancedSignal]:
    """
    Check URL shortener domains.
    Differentiates between verified official brand shorteners (e.g. youtu.be, ig.me)
    and generic third-party shorteners (e.g. bit.ly, tinyurl.com).
    """
    dom = root_domain.lower().strip()
    if dom in OFFICIAL_SHORTENERS:
        return [AdvancedSignal(
            check=f"Official short-link domain: {dom}",
            severity="safe",
            explanation=f"'{dom}' is an official short-link domain operated by a verified service.",
        )]
    if dom in GENERIC_SHORTENERS:
        return [AdvancedSignal(
            check=f"URL shortener: {dom}",
            severity="medium",
            explanation=(
                f"'{dom}' is a generic third-party URL shortener. Shortened links obscure the final destination. "
                "Be cautious before following."
            ),
        )]
    return []


def check_fresh_domain_pattern(domain_label: str) -> list[AdvancedSignal]:
    """Heuristic signals that suggest a freshly registered throwaway domain."""
    signals = []
    for pattern in FRESH_DOMAIN_SIGNALS:
        if re.search(pattern, domain_label, re.IGNORECASE):
            signals.append(AdvancedSignal(
                check="Fresh/auto-generated domain pattern",
                severity="medium",
                explanation=(
                    f"The domain label '{domain_label}' matches patterns common in auto-generated "
                    "or freshly registered domains (long numbers, stacked keywords, random strings). "
                    "Phishing domains are often registered hours before an attack and abandoned quickly."
                ),
            ))
            break  # one signal per domain is enough
    return signals


def check_data_uri(url: str) -> list[AdvancedSignal]:
    """Detect data: and javascript: URI schemes."""
    url_lower = url.lower().strip()
    if url_lower.startswith("javascript:"):
        return [AdvancedSignal(
            check="JavaScript URI scheme",
            severity="critical",
            explanation=(
                "This is a 'javascript:' URI. Clicking it runs arbitrary JavaScript code directly "
                "in your browser. Legitimate sites never send links with this scheme. "
                "This is used to steal cookies, redirect browsers, or execute malware."
            ),
        )]
    if url_lower.startswith("data:"):
        return [AdvancedSignal(
            check="Data URI scheme",
            severity="critical",
            explanation=(
                "This is a 'data:' URI that embeds content directly in the URL. "
                "Attackers use data URIs to render fake login pages entirely within the URL bar, "
                "making them impossible to detect by domain. Never interact with data: URLs from untrusted sources."
            ),
        )]
    return []


def score_radar(url_result=None, msg_result=None) -> dict:
    """
    Produce a radar-chart-friendly 5-axis threat breakdown (0-100 each):
      - Deception     : impersonation, typosquatting, homograph
      - Credential Risk: login/verify/password/OTP paths
      - Urgency/Pressure: time pressure, threat language
      - Technical Risk  : IP host, HTTP, suspicious TLD, entropy
      - Social Engineering: prize/free/lure, secrecy
    """
    axes = {
        "Deception": 0,
        "Credential Risk": 0,
        "Urgency": 0,
        "Technical": 0,
        "Social Engineering": 0,
    }

    if url_result:
        ev_signals = " ".join(e.signal.lower() + " " + e.explanation.lower() for e in url_result.evidence)
        if any(k in ev_signals for k in ["impersonat", "typosquat", "homograph", "idn"]):
            axes["Deception"] += 80
        if any(k in ev_signals for k in ["credential", "login", "verify", "password", "pin"]):
            axes["Credential Risk"] += 70
        if "urgency" in ev_signals:
            axes["Urgency"] += 60
        if any(k in ev_signals for k in ["ip address", "http", "suspicious tld", "entropy", "random"]):
            axes["Technical"] += min(url_result.risk_score, 80)
        if any(k in ev_signals for k in ["redirect", "shortened", "open-redirect"]):
            axes["Social Engineering"] += 50
        axes["Technical"] = max(axes["Technical"], int(url_result.risk_score * 0.6))

    if msg_result:
        sc = msg_result.signal_counts
        axes["Urgency"]            = min(100, axes["Urgency"] + sc.get("urgency", 0) * 25)
        axes["Social Engineering"] = min(100, axes["Social Engineering"] + sc.get("financial_lure", 0) * 20)
        axes["Credential Risk"]    = min(100, axes["Credential Risk"] + sc.get("credential_harvesting", 0) * 30)
        axes["Deception"]          = min(100, axes["Deception"] + sc.get("impersonation", 0) * 25)
        axes["Technical"]          = min(100, axes["Technical"] + sc.get("suspicious_links", 0) * 30)

    # Clamp all to [0, 100]
    return {k: min(100, v) for k, v in axes.items()}
