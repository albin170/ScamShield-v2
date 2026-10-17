"""
Message Analyzer — Rule-based + lightweight ML-inspired classifier
for SMS, email, and social-media scam messages.
"""
import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Signal dictionaries
# ---------------------------------------------------------------------------

URGENCY_PATTERNS = [
    (r"\burgent\b", "Urgency trigger: 'urgent'"),
    (r"\bact now\b", "Urgency trigger: 'act now'"),
    (r"\bimmediately\b", "Urgency trigger: 'immediately'"),
    (r"\bexpir(e|es|ing|ed)\b", "Expiration pressure"),
    (r"\blimited time\b", "Artificial scarcity: 'limited time'"),
    (r"\blast chance\b", "Artificial scarcity: 'last chance'"),
    (r"\bdeadline\b", "Deadline pressure"),
    (r"\bdon'?t delay\b", "Urgency trigger: 'don't delay'"),
    (r"\bwithin \d+ hours?\b", "Tight time-window pressure"),
    (r"\btoday only\b", "Artificial scarcity: 'today only'"),
]

FINANCIAL_BAIT_PATTERNS = [
    (r"\bfree\b", "Freebie lure"),
    (r"\bwon\b|\bwinner\b", "Lottery/prize claim"),
    (r"\bcongratulations\b", "Prize announcement"),
    (r"\bprize\b", "Prize mention"),
    (r"\breward\b", "Reward offer"),
    (r"\bcashback\b", "Cashback lure"),
    (r"\bgrant\b", "Grant offer"),
    (r"\binherit\b|\binheritance\b", "Inheritance scam signal"),
    (r"\bmillion(s)?\b", "Large-sum claim"),
    (r"\bunclaimed\b", "Unclaimed funds lure"),
    (r"\brefund\b", "False refund offer"),
    (r"\blottery\b", "Lottery claim"),
    (r"\b(lakh|crore|crores)\b", "High-value currency lure"),
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r"\bverify\b|\bverification\b", "Credential verification request"),
    (r"\bconfirm.{0,20}(account|identity|detail)", "Account confirmation request"),
    (r"\bupdate.{0,20}(account|info|detail|password)", "Account update request"),
    (r"\bpassword\b", "Password mention"),
    (r"\bpin\b|\bpin number\b", "PIN request"),
    (r"\bOTP\b|\bone.?time.?pass", "OTP request"),
    (r"\bsocial security\b|\bSSN\b", "SSN request"),
    (r"\bbank.{0,15}detail", "Banking details request"),
    (r"\bcredit card\b|\bcard number\b|\bcvv\b", "Card data request"),
    (r"\baadhaar\b|\bpan card\b", "Government ID request (India-specific)"),
]

IMPERSONATION_PATTERNS = [
    (r"\b(IRS|income tax|tax department)\b", "Government agency impersonation"),
    (r"\bRBI\b|\bReserve Bank\b", "RBI impersonation"),
    (r"\b(FBI|CIA|Interpol|police|court)\b", "Law enforcement impersonation"),
    (r"\bMicrosoft\b.{0,40}(support|technical|team)", "Tech support scam"),
    (r"\bApple\b.{0,40}(support|ID|account)", "Apple impersonation"),
    (r"\bPayPal\b.{0,20}(alert|suspended|limited)", "PayPal impersonation"),
    (r"\bAmazon\b.{0,30}(order|account|suspended)", "Amazon impersonation"),
    (r"\b(Netflix|Spotify)\b.{0,30}(payment|renew|suspend)", "Streaming service impersonation"),
    (r"\byour bank\b|\bbank alert\b|\bbank account\b.{0,20}(suspend|block|lock)", "Bank impersonation"),
    (r"\b(KBC|Kaun Banega Crorepati)\b", "KBC lottery impersonation"),
    (r"\bCustomer (Care|Service|Support)\b", "Fake customer support claim"),
]

THREAT_PATTERNS = [
    (r"\bsuspended\b|\bblocked\b", "Account suspension threat"),
    (r"\baction required\b", "Forced action language"),
    (r"\byour account.{0,20}(hack|comprom|breach)", "Security breach claim"),
    (r"\blegal action\b|\bpolice\b.{0,20}report", "Legal threat"),
    (r"\bwarrant\b|\barrest\b", "Arrest/warrant threat"),
    (r"\bunusual (activity|login|sign.?in)", "Fake security alert"),
    (r"\bdetected.{0,20}(virus|malware|hack)", "Fake malware alert"),
]

SUSPICIOUS_LINK_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Raw IP address link"),
    (r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link|rb\.gy|cutt\.ly", "Shortened/obfuscated URL"),
    (r"\.(tk|ml|ga|cf|gq|xyz|top|win|loan|click)(/|$)", "Suspicious TLD in link"),
    (r"https?://[^\s]{100,}", "Extremely long URL in message"),
]

INFORMAL_SIGNALS = [
    (r"dear (customer|user|member|friend|beneficiary)", "Generic salutation — no name used"),
    (r"click (here|below|the link)", "'Click here' prompt — common phishing CTA"),
    (r"do not (share|disclose|tell)", "Secrecy instruction — a red flag"),
    (r"keep (this|it) (confidential|secret|private)", "Secrecy instruction"),
    (r"claim your", "Claim prompt"),
]

JOB_SCAM_PATTERNS = [
    (r"\b(part.?time|work from home|remote job)\b.{0,30}(daily|per day|earn|salary|hourly)", "Fake work-from-home job promise"),
    (r"\bearn \d{3,5}\b.{0,20}(daily|per day|hour|today)", "Unrealistic daily wage promise"),
    (r"\b(like|subscribe|review).{0,20}(youtube|telegram|google maps).{0,20}(earn|money|paid)", "Task/YouTube rating job scam"),
    (r"\btelegram.{0,25}(hr|recruiter|manager|task|team)", "Recruiter moving conversation to Telegram"),
    (r"\bregistration fee\b|\bsecurity deposit\b.{0,20}job", "Advance fee job fraud"),
]

CRYPTO_INVESTMENT_PATTERNS = [
    (r"\b(guaranteed|risk.?free)\b.{0,25}(return|profit|yield|roi)", "Guaranteed profit claim (Ponzi/crypto signal)"),
    (r"\b(crypto|bitcoin|usdt|eth|mining)\b.{0,30}(double|profit|invest|airdrop)", "Crypto investment/airdrop bait"),
    (r"\bdeposit.{0,20}(get|earn|double).{0,15}(bonus|profit)", "Deposit doubling scheme"),
    (r"\btrading signals\b|\bvip trading group\b", "Forex/crypto signal scam channel"),
    (r"\bconnect wallet\b|\bseed phrase\b|\bprivate key\b", "Web3 wallet drainer / seed phrase request"),
]


@dataclass
class MessageEvidence:
    category: str
    signal: str
    severity: str
    explanation: str
    matched_text: str = ""


@dataclass
class MessageAnalysisResult:
    text: str
    risk_level: str
    risk_score: int
    evidence: list[MessageEvidence] = field(default_factory=list)
    summary: str = ""
    next_steps: list[str] = field(default_factory=list)
    extracted_urls: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    signal_counts: dict = field(default_factory=dict)


def _find_patterns(text: str, patterns: list, category: str, severity: str, base_explanation: str) -> list[MessageEvidence]:
    results = []
    text_lower = text.lower()
    for pattern, signal in patterns:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            results.append(MessageEvidence(
                category=category,
                signal=signal,
                severity=severity,
                explanation=base_explanation,
                matched_text=match.group(0),
            ))
    return results


def _extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(
        r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    )
    return url_pattern.findall(text)


def analyze_message(text: str) -> MessageAnalysisResult:
    evidence: list[MessageEvidence] = []
    score = 0

    # ── 1. Urgency signals ──────────────────────────────────────────────────
    urgency = _find_patterns(text, URGENCY_PATTERNS, "Urgency Tactic", "medium",
        "Scammers create false time pressure to stop you from thinking critically. "
        "Legitimate services rarely demand immediate action.")
    evidence.extend(urgency)
    score += min(len(urgency) * 10, 25)

    # ── 2. Financial bait ───────────────────────────────────────────────────
    fin = _find_patterns(text, FINANCIAL_BAIT_PATTERNS, "Financial Lure", "high",
        "Promises of prizes, free money, or rewards are classic social engineering. "
        "If it sounds too good to be true, it almost certainly is.")
    evidence.extend(fin)
    score += min(len(fin) * 15, 45)

    # ── 3. Credential harvesting ────────────────────────────────────────────
    cred = _find_patterns(text, CREDENTIAL_HARVEST_PATTERNS, "Credential Harvesting", "critical",
        "Legitimate services never ask for passwords, OTPs, PINs, or card details via SMS or email. "
        "This is a hallmark of phishing.")
    evidence.extend(cred)
    score += min(len(cred) * 15, 40)

    # ── 4. Impersonation ────────────────────────────────────────────────────
    imp = _find_patterns(text, IMPERSONATION_PATTERNS, "Impersonation", "high",
        "This message claims to be from a well-known organisation. "
        "Always verify by contacting the organisation directly through their official website, not via the link in this message.")
    evidence.extend(imp)
    score += min(len(imp) * 12, 30)

    # ── 5. Threats ──────────────────────────────────────────────────────────
    threats = _find_patterns(text, THREAT_PATTERNS, "Threat / Fear Tactic", "high",
        "Threatening consequences (account suspension, legal action, arrest) are used to panic victims into compliance. "
        "Legitimate organisations handle disputes through official letters, not unsolicited messages.")
    evidence.extend(threats)
    score += min(len(threats) * 12, 30)

    # ── 6. Suspicious links in message ─────────────────────────────────────
    link_ev = _find_patterns(text, SUSPICIOUS_LINK_PATTERNS, "Suspicious Link", "high",
        "The message contains a link with suspicious characteristics. "
        "Shortened URLs hide the real destination. IP-based URLs are almost never used by legitimate services.")
    evidence.extend(link_ev)
    score += min(len(link_ev) * 15, 30)

    # ── 7. Informal / generic signals ──────────────────────────────────────
    informal = _find_patterns(text, INFORMAL_SIGNALS, "Informal Signal", "low",
        "Generic greetings, 'click here' prompts, or secrecy instructions are common in scam messages.")
    evidence.extend(informal)
    score += min(len(informal) * 5, 15)

    # ── 7b. Job & Task scam signals ─────────────────────────────────────────
    jobs = _find_patterns(text, JOB_SCAM_PATTERNS, "Job / Task Scam", "high",
        "Fake employment and task scams promise high daily returns for simple tasks or require upfront fees. "
        "Legitimate employers never hire through anonymous Telegram channels or demand payment to work.")
    evidence.extend(jobs)
    score += min(len(jobs) * 18, 55)

    # ── 7c. Crypto & Investment scam signals ────────────────────────────────
    crypto = _find_patterns(text, CRYPTO_INVESTMENT_PATTERNS, "Crypto / Investment Fraud", "critical",
        "Guaranteed returns and seed phrase requests are hallmarks of financial fraud and wallet-draining exploits. "
        "Never share secret phrases or private keys with anyone.")
    evidence.extend(crypto)
    score += min(len(crypto) * 16, 40)

    # ── 7d. Synergy heuristics (Multi-factor scam combinations) ────────────
    # Secrecy demand + Financial bait (Classic advance fee / lottery fraud)
    has_secrecy = any("secrecy" in e.signal.lower() for e in informal)
    if has_secrecy and fin:
        score += 20
        evidence.append(MessageEvidence(
            category="Social Engineering",
            signal="Prize lure combined with secrecy demand",
            severity="critical",
            explanation="Demanding confidentiality or secrecy while offering a lottery, prize, or reward is a classic mark of advance-fee fraud.",
        ))

    # Job scam with Telegram diversion
    has_telegram = any("telegram" in e.signal.lower() for e in jobs)
    if has_telegram and len(jobs) >= 2:
        score += 15
        evidence.append(MessageEvidence(
            category="Job / Task Scam",
            signal="High-yield job redirecting to encrypted messaging",
            severity="critical",
            explanation="Redirecting job candidates to anonymous Telegram recruiters while promising high daily pay is standard operating procedure for task scam rings.",
        ))

    # ── 8. Extract URLs ──────────────────────────────────────────────────────
    extracted_urls = _extract_urls(text)

    # ── 9. Text length / complexity checks ──────────────────────────────────
    # Very short messages with a link are suspicious
    words = text.split()
    if len(words) < 15 and extracted_urls:
        score += 10
        evidence.append(MessageEvidence(
            category="Structure",
            signal="Very short message with link",
            severity="medium",
            explanation="Extremely short messages that contain only a link provide no context — typical of SMS phishing (smishing).",
        ))

    # All-caps sections
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.4 and len(text) > 30:
        score += 8
        evidence.append(MessageEvidence(
            category="Structure",
            signal="Excessive capitalisation",
            severity="low",
            explanation="Overuse of capital letters is a manipulation tactic to convey urgency and authority.",
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

    summary_map = {
        "critical": f"This message shows multiple strong scam indicators. Do NOT respond or click any links. Score: {score}/100.",
        "high": f"This message has several significant warning signs. Treat it as suspicious. Score: {score}/100.",
        "medium": f"This message has some concerning patterns. Verify through official channels. Score: {score}/100.",
        "low": f"This message has minor concerns. Exercise caution. Score: {score}/100.",
        "safe": f"No significant scam indicators detected. Still use common sense. Score: {score}/100.",
    }

    steps_map = {
        "critical": [
            "Do NOT reply, click any link, or call any number in this message.",
            "Block the sender.",
            "Report to your telecom operator / email provider as spam.",
            "Report to the national cybercrime portal (cybercrime.gov.in for India / IC3 for USA).",
            "If you shared any information, contact your bank immediately.",
        ],
        "high": [
            "Do not click any links in this message.",
            "Contact the supposed sender directly through their official website or phone number.",
            "Report the message as spam/phishing on your platform.",
        ],
        "medium": [
            "Verify this message independently before acting on it.",
            "Search the organisation's official website or call their published number.",
            "Do not provide any personal information.",
        ],
        "low": [
            "Confirm the sender's identity before responding.",
            "If in doubt, ignore and delete.",
        ],
        "safe": [
            "Continue practising safe online habits.",
            "Never share OTPs, passwords, or card details — not even with 'customer service'.",
        ],
    }

    signal_counts = {
        "urgency": len(urgency),
        "financial_lure": len(fin),
        "credential_harvesting": len(cred),
        "impersonation": len(imp),
        "threats": len(threats),
        "suspicious_links": len(link_ev),
        "informal": len(informal),
    }

    limitations = [
        "This is pattern-based analysis. Sophisticated messages may evade detection.",
        "A 'safe' rating does not mean the message is genuine.",
        "Always verify via official channels if you are unsure.",
    ]

    return MessageAnalysisResult(
        text=text,
        risk_level=risk_level,
        risk_score=score,
        evidence=evidence,
        summary=summary_map[risk_level],
        next_steps=steps_map[risk_level],
        extracted_urls=extracted_urls,
        limitations=limitations,
        signal_counts=signal_counts,
    )
