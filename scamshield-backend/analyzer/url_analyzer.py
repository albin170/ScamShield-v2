"""
URL Analyzer — ScamShield Production-Grade Detection Pipeline
Evidence-based static & reputation analysis of URLs for phishing, brand impersonation,
and fraudulent infrastructure.

Features:
- Standards-compliant URL parsing and normalization (IDN, Punycode, ports, query params)
- Boundary-aware brand impersonation detection via BrandRegistry
- Integration with external threat-intelligence feeds (URLhaus, VirusTotal, Safe Browsing)
- SSRF-safe redirect inspection
- Four clear verdicts:
  1. MALICIOUS
  2. SUSPICIOUS
  3. NO KNOWN THREAT FOUND
  4. UNKNOWN / UNABLE TO VERIFY
- Explainable risk scoring with positive and negative evidence attribution
"""
import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.advanced_checks import (
    check_typosquatting, check_homograph, check_url_shortener,
    check_fresh_domain_pattern, check_data_uri, AdvancedSignal,
)
from analyzer.brand_registry import (
    is_official_domain, check_brand_impersonation, extract_domain_info,
    ALL_OFFICIAL_DOMAINS, ALL_OFFICIAL_SHORTENERS,
)
from analyzer.threat_intel import threat_intel_manager, ThreatIntelResult
from analyzer.redirect_service import trace_redirects_safely, is_safe_ip

# Free / disposable TLDs commonly abused
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom free TLDs
    ".xyz", ".top", ".win", ".loan", ".club", ".online",
    ".site", ".store", ".info", ".biz", ".work", ".click",
    ".vip", ".monster", ".quest", ".rest", ".cam", ".bar",
}

SAFE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co.uk", ".in", ".dev", ".ai"}


@dataclass
class URLEvidence:
    signal: str
    severity: str  # "critical" | "high" | "medium" | "low" | "safe" | "info"
    explanation: str
    category: Optional[str] = None
    matched_text: Optional[str] = None


@dataclass
class URLAnalysisResult:
    url: str
    risk_level: str                # "safe" | "low" | "medium" | "high" | "critical" (compatibility)
    risk_score: int                # 0-100
    verdict: str = "NO KNOWN THREAT FOUND"  # "MALICIOUS" | "SUSPICIOUS" | "NO KNOWN THREAT FOUND" | "UNKNOWN / UNABLE TO VERIFY"
    confidence: str = "medium"     # "high" | "medium" | "low"
    evidence: list[URLEvidence] = field(default_factory=list)
    positive_evidence: list[URLEvidence] = field(default_factory=list)
    negative_evidence: list[URLEvidence] = field(default_factory=list)
    sources_consulted: list[str] = field(default_factory=list)
    checks_completed: list[str] = field(default_factory=list)
    checks_unavailable: list[str] = field(default_factory=list)
    summary: str = ""
    next_steps: list[str] = field(default_factory=list)
    is_https: bool = False
    domain: str = ""
    normalized_url: str = ""
    has_ip_host: bool = False
    redirect_chain_depth: int = 0
    limitations: list[str] = field(default_factory=list)
    analysis_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _entropy(text: str) -> float:
    """Shannon entropy — high entropy in subdomains suggests algorithmically generated domains."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def normalize_url(raw_url: str) -> tuple[str, Optional[object], Optional[str]]:
    """
    Standards-compliant URL parser and normalizer.
    Returns (normalized_url, parsed_obj, error_message).
    """
    trimmed = raw_url.strip()
    if not trimmed:
        return "", None, "Empty URL provided."

    # Check for dangerous schemes before prefixing
    low = trimmed.lower()
    if low.startswith(("javascript:", "data:", "vbscript:", "file:")):
        return trimmed, None, None

    # Default to https:// if scheme is missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed):
        target = "https://" + trimmed
        assumed_scheme = True
    else:
        target = trimmed
        assumed_scheme = False

    try:
        parsed = urlparse(target)
    except Exception as e:
        return trimmed, None, f"Malformed URL syntax: {str(e)[:150]}"

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Handle Punycode / IDN encoding
    try:
        import idna
        host_parts = netloc.split("@")[-1].split(":")[0].split(".")
        encoded_parts = [idna.encode(p).decode("ascii") if p else "" for p in host_parts]
        ascii_netloc = ".".join(encoded_parts)
    except Exception:
        ascii_netloc = netloc

    # Remove standard default ports
    if ascii_netloc.endswith(":443") and scheme == "https":
        ascii_netloc = ascii_netloc[:-4]
    elif ascii_netloc.endswith(":80") and scheme == "http":
        ascii_netloc = ascii_netloc[:-3]

    path = parsed.path or "/"
    norm_url = f"{scheme}://{ascii_netloc}{path}"
    if parsed.query:
        norm_url += f"?{parsed.query}"

    return norm_url, parsed, None


def analyze_url(
    url: str,
    enable_threat_intel: bool = True,
    follow_redirects: bool = False,
) -> URLAnalysisResult:
    """
    Production-grade URL security evaluation pipeline.
    Produces an explainable risk score, structured evidence, and one of 4 clear verdicts.
    """
    raw_url = url.strip()
    normalized_url, parsed, parse_error = normalize_url(raw_url)

    # ── Handle Malformed or Unsupported URLs ────────────────────────────────
    if parse_error or not parsed:
        # Check if it was a dangerous raw scheme like javascript:
        if raw_url.lower().startswith(("javascript:", "data:")):
            ev = URLEvidence(
                signal="Dangerous URI scheme",
                severity="critical",
                explanation=f"URLs starting with '{raw_url.split(':')[0]}:' can execute code directly. Never open these.",
                category="Code Execution",
            )
            return URLAnalysisResult(
                url=raw_url,
                normalized_url=raw_url,
                verdict="MALICIOUS",
                risk_level="critical",
                risk_score=95,
                confidence="high",
                evidence=[ev],
                negative_evidence=[ev],
                summary="Malicious URI scheme detected: execution of arbitrary script or payload.",
                next_steps=["Do not interact with or click this link.", "Delete the message containing this link."],
                sources_consulted=["URI Scheme Validator"],
                checks_completed=["URI Scheme Analysis"],
            )

        ev = URLEvidence(
            signal="Malformed URL syntax",
            severity="high",
            explanation=parse_error or "The URL could not be parsed according to standard RFC specifications.",
            category="Format",
        )
        return URLAnalysisResult(
            url=raw_url,
            normalized_url=raw_url,
            verdict="UNKNOWN / UNABLE TO VERIFY",
            risk_level="high",
            risk_score=75,
            confidence="low",
            evidence=[ev],
            negative_evidence=[ev],
            summary="Unable to verify URL: input is malformed or invalid.",
            next_steps=["Check the link for typos.", "Do not click unverified or broken links."],
            sources_consulted=["RFC 3986 URL Parser"],
            checks_completed=["Syntax Validation"],
            checks_unavailable=["Domain Analysis", "Threat Intelligence"],
        )

    hostname = (parsed.hostname or "").lower().rstrip(".")
    subdomain, root_domain, domain_label, suffix = extract_domain_info(hostname)
    path = parsed.path or ""
    query = parsed.query or ""
    full_path = path + ("?" + query if query else "")
    is_https = parsed.scheme.lower() == "https"

    evidence: list[URLEvidence] = []
    positive_evidence: list[URLEvidence] = []
    negative_evidence: list[URLEvidence] = []
    sources_consulted: list[str] = ["RFC 3986 URL Parser", "ScamShield Heuristic Engine", "Brand Registry"]
    checks_completed: list[str] = [
        "Hostname Structure Analysis",
        "TLD Inspection",
        "Brand Impersonation Check",
        "Punycode & Homoglyph Inspection",
        "Credential & Path Analysis",
    ]
    checks_unavailable: list[str] = []

    score = 0
    threat_intel_match = False
    threat_intel_clean_count = 0

    # ── 1. Official Brand / Whitelist Check ──────────────────────────────────
    official_brand = is_official_domain(hostname)
    is_official = official_brand is not None

    if is_official:
        ev = URLEvidence(
            signal=f"Recognised official domain: {official_brand.display_name}",
            severity="safe",
            explanation=(
                f"'{hostname}' is an official domain registered to {official_brand.display_name}. "
                f"Verified against official directory (Last audited: {official_brand.last_verified})."
            ),
            category="Domain Authentication",
        )
        positive_evidence.append(ev)
        evidence.append(ev)
    elif root_domain in ALL_OFFICIAL_DOMAINS:
        ev = URLEvidence(
            signal=f"Recognised legitimate domain: {root_domain}",
            severity="safe",
            explanation=f"'{root_domain}' is an established, well-known internet service.",
            category="Domain Authentication",
        )
        positive_evidence.append(ev)
        evidence.append(ev)

    # ── 2. HTTPS & Transport Security ───────────────────────────────────────
    if is_https:
        ev = URLEvidence(
            signal="HTTPS present",
            severity="safe",
            explanation="The connection uses HTTPS encryption. Note: encryption prevents eavesdropping but does not guarantee the site is benign.",
            category="Transport Security",
        )
        positive_evidence.append(ev)
        evidence.append(ev)
    else:
        # Non-HTTPS penalty is smaller for official domains or standard browsing
        penalty = 10 if is_official else 20
        score += penalty
        ev = URLEvidence(
            signal="No HTTPS encryption",
            severity="medium" if is_official else "high",
            explanation="The URL uses unencrypted HTTP. Data entered on this page can be intercepted in transit.",
            category="Transport Security",
        )
        negative_evidence.append(ev)
        evidence.append(ev)

    # ── 3. Hostname & IP Host Check ──────────────────────────────────────────
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip = bool(ip_pattern.match(hostname)) or (":" in hostname and not hostname.startswith("["))

    if has_ip:
        is_safe_public = is_safe_ip(hostname)
        if not is_safe_public:
            score += 50
            ev = URLEvidence(
                signal="Private/Internal IP address in host",
                severity="critical",
                explanation=f"The host '{hostname}' references a private, loopback, or cloud-metadata network (SSRF risk).",
                category="Infrastructure Risk",
            )
        else:
            score += 35
            ev = URLEvidence(
                signal="Raw IP address used instead of domain name",
                severity="high",
                explanation=f"The host is a raw IP address ({hostname}). Legitimate web platforms use registered domain names.",
                category="Infrastructure Risk",
            )
        negative_evidence.append(ev)
        evidence.append(ev)

    # ── 4. Brand Impersonation Check (Boundary-Aware) ─────────────────────────
    if not is_official:
        impersonation = check_brand_impersonation(hostname)
        if impersonation and impersonation.is_impersonation:
            score += 45
            ev = URLEvidence(
                signal=f"Brand impersonation detected: {impersonation.brand.display_name}",
                severity="critical",
                explanation=impersonation.reason,
                category="Brand Deception",
                matched_text=impersonation.details,
            )
            negative_evidence.append(ev)
            evidence.append(ev)

    # ── 5. IDN Homograph & Punycode Analysis ─────────────────────────────────
    homograph_sigs = check_homograph(hostname)
    for sig in homograph_sigs:
        score += 35
        ev = URLEvidence(
            signal=sig.check,
            severity=sig.severity,
            explanation=f"{sig.explanation} (Detail: {sig.detail})" if sig.detail else sig.explanation,
            category="Visual Deception",
        )
        negative_evidence.append(ev)
        evidence.append(ev)

    # ── 6. Typosquatting Analysis (Only for Non-Official Domains) ─────────────
    if not is_official and not has_ip:
        typo_sigs = check_typosquatting(domain_label, hostname=hostname)
        for sig in typo_sigs:
            score += 30 if sig.severity == "critical" else 20
            ev = URLEvidence(
                signal=sig.check,
                severity=sig.severity,
                explanation=f"{sig.explanation} (Detail: {sig.detail})" if sig.detail else sig.explanation,
                category="Typosquatting",
            )
            negative_evidence.append(ev)
            evidence.append(ev)

    # ── 7. Shortener & Cloaking Checks ───────────────────────────────────────
    shortener_sigs = check_url_shortener(root_domain)
    for sig in shortener_sigs:
        if sig.severity == "safe":
            ev = URLEvidence(signal=sig.check, severity="safe", explanation=sig.explanation, category="Routing")
            positive_evidence.append(ev)
            evidence.append(ev)
        else:
            score += 12
            ev = URLEvidence(signal=sig.check, severity=sig.severity, explanation=sig.explanation, category="Routing")
            negative_evidence.append(ev)
            evidence.append(ev)

    # ── 8. Suspicious TLD & Fresh Domain Patterns ────────────────────────────
    tld = "." + root_domain.split(".")[-1] if "." in root_domain else ""
    if tld in SUSPICIOUS_TLDS and not is_official:
        score += 20
        ev = URLEvidence(
            signal=f"Abused top-level domain: {tld}",
            severity="medium",
            explanation=f"The TLD '{tld}' is frequently associated with disposable, free, or low-cost domain registrations.",
            category="Reputation",
        )
        negative_evidence.append(ev)
        evidence.append(ev)

    if not is_official and not has_ip:
        fresh_sigs = check_fresh_domain_pattern(domain_label)
        for sig in fresh_sigs:
            score += 15
            ev = URLEvidence(signal=sig.check, severity=sig.severity, explanation=sig.explanation, category="Domain Pattern")
            negative_evidence.append(ev)
            evidence.append(ev)

    # ── 9. Subdomain Structure & Domain Entropy ──────────────────────────────
    if not is_official and not has_ip:
        sub_parts = subdomain.split(".") if subdomain else []
        if len(sub_parts) >= 3:
            score += 15
            ev = URLEvidence(
                signal=f"Excessive subdomain nesting ({len(sub_parts)} levels)",
                severity="medium",
                explanation=f"Hostname has {len(sub_parts)} subdomain levels ('{subdomain}'). Attackers use multi-level subdomains to hide real domain names.",
                category="Domain Structure",
            )
            negative_evidence.append(ev)
            evidence.append(ev)

        ent = _entropy(domain_label)
        if ent > 3.8 and len(domain_label) > 9:
            score += 15
            ev = URLEvidence(
                signal="High-entropy domain label",
                severity="medium",
                explanation=f"The domain label '{domain_label}' exhibits high randomness (entropy: {ent:.2f}), common in algorithmic domain generation.",
                category="Domain Structure",
            )
            negative_evidence.append(ev)
            evidence.append(ev)

    # ── 10. URL Credentials & Path Heuristics ────────────────────────────────
    if parsed.username or parsed.password:
        score += 35
        ev = URLEvidence(
            signal="Embedded user credentials in URL",
            severity="critical",
            explanation="The URL contains embedded user credentials (user:pass@host). This is commonly used in link obfuscation to deceive users.",
            category="Obfuscation",
        )
        negative_evidence.append(ev)
        evidence.append(ev)

    # Credential path checks (only penalized if NOT an official domain)
    path_lower = full_path.lower()
    path_hits = [kw for kw in ["login", "verify", "account", "update", "confirm", "password", "credential", "auth", "wallet"] if kw in path_lower]
    if path_hits and not is_official:
        score += min(len(path_hits) * 8, 24)
        ev = URLEvidence(
            signal=f"Credential-related path terms: {', '.join(path_hits[:3])}",
            severity="medium",
            explanation="Path contains credential-sensitive keywords on an unverified domain.",
            category="Phishing Indicators",
        )
        negative_evidence.append(ev)
        evidence.append(ev)

    # Open-redirect parameters (e.g. ?redirect=http://evil.com)
    qs = parse_qs(query)
    redirect_params = [p for p in qs if p.lower() in ("url", "redirect", "goto", "next", "return", "redir", "link", "target")]
    if redirect_params and not is_official:
        score += 12
        ev = URLEvidence(
            signal=f"Potential open-redirect parameter: {', '.join(redirect_params)}",
            severity="medium",
            explanation="Query parameter may chain browser navigation through to an unverified target.",
            category="Routing",
        )
        negative_evidence.append(ev)
        evidence.append(ev)

    # ── 11. External Threat Intelligence Integration ────────────────────────
    if enable_threat_intel:
        sources_consulted.extend(["URLhaus (abuse.ch)", "VirusTotal", "Google Safe Browsing"])
        checks_completed.append("Threat Intelligence Lookup")
        ti_results = threat_intel_manager.query_all(normalized_url)

        for ti in ti_results:
            if ti.status == "match" and ti.is_malicious:
                threat_intel_match = True
                score = max(score, 88)
                ev = URLEvidence(
                    signal=f"Threat-Intelligence Match: {ti.provider}",
                    severity="critical",
                    explanation=ti.details,
                    category="Confirmed Threat",
                )
                negative_evidence.append(ev)
                evidence.append(ev)
            elif ti.status == "clean":
                threat_intel_clean_count += 1
            elif ti.status in ("unavailable", "rate_limited"):
                checks_unavailable.append(f"{ti.provider} ({ti.status})")
    else:
        checks_unavailable.append("External Threat Intelligence (disabled by configuration)")

    # ── 12. Safe Redirect Analysis (Optional / Configured) ───────────────────
    redirect_depth = 0
    if follow_redirects:
        checks_completed.append("Safe Redirect Resolution")
        trace_res = trace_redirects_safely(normalized_url)
        redirect_depth = trace_res.depth
        if trace_res.ssrf_blocked:
            score += 50
            ev = URLEvidence(
                signal="SSRF Attack Blocked in Redirect",
                severity="critical",
                explanation=trace_res.error or "Redirect target attempted to reach internal infrastructure.",
                category="SSRF Prevention",
            )
            negative_evidence.append(ev)
            evidence.append(ev)
        elif trace_res.has_loop:
            ev = URLEvidence(
                signal="Redirect Loop Detected",
                severity="medium",
                explanation=trace_res.error or "URL redirected in an infinite cycle.",
                category="Routing",
            )
            negative_evidence.append(ev)
            evidence.append(ev)

    # ── 13. Official Domain Score Normalization ──────────────────────────────
    if is_official:
        # Verified official domains should not be penalized by routine heuristics
        score = min(score, 10) if not threat_intel_match else score

    score = max(0, min(score, 100))

    # ── 14. Phase 5: Four Clear Verdicts ────────────────────────────────────
    if threat_intel_match or score >= 85:
        verdict = "MALICIOUS"
        risk_level = "critical"
        confidence = "high"
    elif score >= 35 or any(e.severity in ("critical", "high") for e in negative_evidence):
        verdict = "SUSPICIOUS"
        risk_level = "high" if score >= 55 else "medium"
        confidence = "high" if len(negative_evidence) >= 2 else "medium"
    elif is_official or (score < 25 and len(negative_evidence) == 0):
        verdict = "NO KNOWN THREAT FOUND"
        risk_level = "safe" if score <= 5 else "low"
        confidence = "high" if is_official else "medium"
    else:
        verdict = "UNKNOWN / UNABLE TO VERIFY"
        risk_level = "low"
        confidence = "low"

    # ── Summary & Recommendations ───────────────────────────────────────────
    summary_map = {
        "MALICIOUS": f"MALICIOUS: Credible threat detected ({score}/100). Do NOT visit this link or enter any data.",
        "SUSPICIOUS": f"SUSPICIOUS: Risk indicators detected ({score}/100). Maliciousness not conclusively confirmed, but caution is required.",
        "NO KNOWN THREAT FOUND": f"NO KNOWN THREAT FOUND: Completed checks did not identify known indicators ({score}/100). Still exercise standard caution.",
        "UNKNOWN / UNABLE TO VERIFY": f"UNKNOWN / UNABLE TO VERIFY: Insufficient evidence available to verify safety ({score}/100).",
    }

    steps_map = {
        "MALICIOUS": [
            "Do NOT visit this link.",
            "Block the sender and report the link to the hosting provider or platform.",
            "If you entered credentials, change them immediately from an official device.",
        ],
        "SUSPICIOUS": [
            "Do not enter passwords, credit cards, or personal information.",
            "Navigate to the official website directly via a search engine rather than clicking this link.",
            "Verify the sender's identity through an independent communication channel.",
        ],
        "NO KNOWN THREAT FOUND": [
            "Verify that the web address matches what you expect before signing in.",
            "Ensure the site connection is encrypted with HTTPS.",
            "Never share 2FA codes or one-time passwords.",
        ],
        "UNKNOWN / UNABLE TO VERIFY": [
            "Proceed only if you know and trust the sender.",
            "Check domain registration details independently.",
        ],
    }

    limitations = [
        "Static heuristic and reputation analysis does not execute JavaScript or render active payloads.",
        "No known threat found does NOT guarantee that an unlisted or novel zero-day website is safe.",
        "Sophisticated attackers frequently obtain valid TLS certificates and use HTTPS.",
    ]

    return URLAnalysisResult(
        url=raw_url,
        normalized_url=normalized_url,
        risk_level=risk_level,
        risk_score=score,
        verdict=verdict,
        confidence=confidence,
        evidence=evidence,
        positive_evidence=positive_evidence,
        negative_evidence=negative_evidence,
        sources_consulted=sources_consulted,
        checks_completed=checks_completed,
        checks_unavailable=checks_unavailable,
        summary=summary_map[verdict],
        next_steps=steps_map[verdict],
        is_https=is_https,
        domain=root_domain,
        has_ip_host=has_ip,
        redirect_chain_depth=redirect_depth,
        limitations=limitations,
    )
