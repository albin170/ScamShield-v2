"""
ScamShield FastAPI Backend — v3.0
Evidence-based scam, phishing, and fraud detection.

New in v3:
  - Super admin + admin authentication (JWT, HttpOnly cookies)
  - Role-based access control (superadmin / admin / user / guest)
  - Admin panel API: user management, audit log, session control
  - Theme management via database
  - Notifications system
  - Rate limiting on auth endpoints
  - Secure super admin bootstrap via environment variable
"""
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Load .env before anything else
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass  # python-dotenv optional

from fastapi import FastAPI, HTTPException, APIRouter, File, Form, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    limiter = Limiter(key_func=get_remote_address)
    RATE_LIMIT_ENABLED = True
except ImportError:
    limiter = None
    RATE_LIMIT_ENABLED = False

import sys
sys.path.insert(0, str(Path(__file__).parent))

from analyzer.url_analyzer import analyze_url, URLAnalysisResult, URLEvidence
from analyzer.message_analyzer import analyze_message, MessageAnalysisResult, MessageEvidence
from analyzer.email_analyzer import analyze_email, EmailAnalysisResult, EmailEvidence
from analyzer.qr_analyzer import analyze_qr, QRAnalysisResult
from analyzer.file_analyzer import analyze_file, FileAnalysisResult, FileEvidence
from analyzer.threat_intel import threat_intel_manager
from analyzer.benchmark_data import evaluate_dataset, BENCHMARK_DATASET
from database import init_db, bootstrap_superadmin, get_db as get_auth_db
from admin_routes import auth_router, admin_router, superadmin_router, public_settings_router

# ---------------------------------------------------------------------------
# Configuration (from environment variables)
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    orig.strip()
    for orig in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://localhost:3000"
    ).split(",")
    if orig.strip() and orig.strip() != "*"
]

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25")) * 1024 * 1024  # bytes

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ScamShield API",
    description=(
        "Evidence-based scam, phishing, and cybersecurity threat detection. "
        "Supports URL, SMS/message, email header, QR code, file metadata analysis, "
        "plus admin management, RBAC, and theme configuration."
    ),
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Rate limiting
if RATE_LIMIT_ENABLED and limiter:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS (Supports localhost, Vercel deployments, and Render subdomains with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|.*\.vercel\.app|.*\.onrender\.com|.*\.netlify\.app)(:\d+)?$",
    allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    allow_credentials=True,
    expose_headers=["X-Request-ID"],
    max_age=3600,
)


# ---------------------------------------------------------------------------
# SQLite history store (delegated to database.py)
# ---------------------------------------------------------------------------
DB_PATH = Path(__file__).parent / "scamshield.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize all tables (including new auth tables)
init_db()

# Bootstrap super admin from env vars (safe — skips if already exists)
bootstrap_superadmin()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class URLRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        if len(v) > 4096:
            raise ValueError("URL too long (max 4096 characters)")
        return v


class MessageRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def text_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message text must not be empty")
        if len(v) > 50000:
            raise ValueError("Message too long (max 50000 characters)")
        return v


class EmailRequest(BaseModel):
    raw_headers: str = ""
    body: str = ""
    subject: str = ""
    from_addr: str = ""
    reply_to: str = ""

    @field_validator("raw_headers", "body")
    @classmethod
    def not_too_long(cls, v: str) -> str:
        if len(v) > 100000:
            raise ValueError("Input too long (max 100000 characters)")
        return v


class EvidenceOut(BaseModel):
    signal: str
    severity: str
    explanation: str
    category: Optional[str] = None
    matched_text: Optional[str] = None


class ScanResult(BaseModel):
    id: str
    scan_type: str
    risk_level: str
    risk_score: int
    summary: str
    evidence: list[EvidenceOut]
    next_steps: list[str]
    limitations: list[str]
    created_at: str
    # Explainable Scoring & Four Clear Verdicts
    verdict: Optional[str] = None
    confidence: Optional[str] = None
    normalized_url: Optional[str] = None
    positive_evidence: Optional[list[EvidenceOut]] = None
    negative_evidence: Optional[list[EvidenceOut]] = None
    sources_consulted: Optional[list[str]] = None
    checks_completed: Optional[list[str]] = None
    checks_unavailable: Optional[list[str]] = None
    # URL-specific
    url: Optional[str] = None
    domain: Optional[str] = None
    is_https: Optional[bool] = None
    # Message-specific
    extracted_urls: Optional[list[str]] = None
    signal_counts: Optional[dict] = None
    # Email-specific
    subject: Optional[str] = None
    from_addr: Optional[str] = None
    reply_to: Optional[str] = None
    auth_results: Optional[dict] = None
    headers_parsed: Optional[list[str]] = None
    # QR-specific
    decoded_text: Optional[str] = None
    qr_type: Optional[str] = None
    file_sha256: Optional[str] = None
    decode_available: Optional[bool] = None
    # File-specific
    filename: Optional[str] = None
    file_size_bytes: Optional[int] = None
    detected_type: Optional[str] = None
    claimed_extension: Optional[str] = None
    type_mismatch: Optional[bool] = None
    archive_contents: Optional[list[str]] = None
    macro_detected: Optional[bool] = None
    embedded_urls: Optional[list[str]] = None


class HistoryItem(BaseModel):
    id: str
    scan_type: str
    input_preview: str
    risk_level: str
    risk_score: int
    summary: str
    created_at: str


# ---------------------------------------------------------------------------
# Helper converters
# ---------------------------------------------------------------------------
def _ev(e) -> EvidenceOut:
    """Convert any evidence dataclass to EvidenceOut."""
    return EvidenceOut(
        signal=e.signal,
        severity=e.severity,
        explanation=e.explanation,
        category=getattr(e, "category", None),
        matched_text=getattr(e, "matched_text", None) or None,
    )


def save_scan(scan_type: str, input_preview: str, result: ScanResult):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scan_history VALUES (?,?,?,?,?,?,?,?)",
            (
                result.id,
                scan_type,
                input_preview[:200],
                result.risk_level,
                result.risk_score,
                result.summary,
                result.model_dump_json(),
                result.created_at,
            ),
        )
        conn.commit()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
router = APIRouter()


@router.get("/")
def root():
    return {
        "status": "ok",
        "service": "ScamShield API",
        "version": "2.0.0",
        "endpoints": {
            "health": "/health",
            "readiness": "/readiness",
            "docs": "/docs",
            "analyze_url": "/analyze/url",
            "analyze_message": "/analyze/message",
            "analyze_email": "/analyze/email",
            "analyze_qr": "/analyze/qr",
            "analyze_file": "/analyze/file",
            "history": "/history",
            "stats": "/stats",
        },
    }


@router.get("/health")
def health():
    return {"status": "ok", "service": "ScamShield API", "version": "2.0.0"}


@router.get("/readiness")
def readiness():
    """Checks that the database is reachable and returns component status."""
    db_ok = False
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        pass

    # Optional dependency availability
    try:
        from PIL import Image  # noqa
        pil_ok = True
    except ImportError:
        pil_ok = False

    try:
        from pyzbar.pyzbar import decode  # noqa
        pyzbar_ok = True
    except Exception:
        pyzbar_ok = False

    status = "ok" if db_ok else "degraded"
    return {
        "status": status,
        "components": {
            "database": "ok" if db_ok else "error",
            "qr_decode_pil": "ok" if pil_ok else "unavailable",
            "qr_decode_pyzbar": "ok" if pyzbar_ok else "unavailable",
        },
    }


# ── URL Analysis ──────────────────────────────────────────────────────────
@router.post("/analyze/url", response_model=ScanResult)
def analyze_url_endpoint(req: URLRequest):
    raw = analyze_url(req.url)
    result = ScanResult(
        id=str(uuid.uuid4()),
        scan_type="url",
        risk_level=raw.risk_level,
        risk_score=raw.risk_score,
        verdict=getattr(raw, "verdict", "NO KNOWN THREAT FOUND"),
        confidence=getattr(raw, "confidence", "medium"),
        normalized_url=getattr(raw, "normalized_url", raw.url),
        summary=raw.summary,
        evidence=[_ev(e) for e in raw.evidence],
        positive_evidence=[_ev(e) for e in getattr(raw, "positive_evidence", [])],
        negative_evidence=[_ev(e) for e in getattr(raw, "negative_evidence", [])],
        sources_consulted=getattr(raw, "sources_consulted", []),
        checks_completed=getattr(raw, "checks_completed", []),
        checks_unavailable=getattr(raw, "checks_unavailable", []),
        next_steps=raw.next_steps,
        limitations=raw.limitations,
        created_at=now_iso(),
        url=raw.url,
        domain=raw.domain,
        is_https=raw.is_https,
    )
    save_scan("url", req.url[:200], result)
    return result


# ── Message Analysis ───────────────────────────────────────────────────────
@router.post("/analyze/message", response_model=ScanResult)
def analyze_message_endpoint(req: MessageRequest):
    raw = analyze_message(req.text)
    result = ScanResult(
        id=str(uuid.uuid4()),
        scan_type="message",
        risk_level=raw.risk_level,
        risk_score=raw.risk_score,
        summary=raw.summary,
        evidence=[_ev(e) for e in raw.evidence],
        next_steps=raw.next_steps,
        limitations=raw.limitations,
        created_at=now_iso(),
        extracted_urls=raw.extracted_urls,
        signal_counts=raw.signal_counts,
    )
    save_scan("message", req.text[:200], result)
    return result


# ── Email Analysis ─────────────────────────────────────────────────────────
@router.post("/analyze/email", response_model=ScanResult)
def analyze_email_endpoint(req: EmailRequest):
    if not req.raw_headers.strip() and not req.body.strip() and not req.subject.strip() and not req.from_addr.strip():
        raise HTTPException(400, "Provide at least raw headers, a body, or a subject/from address to analyse.")

    raw = analyze_email(
        raw_headers=req.raw_headers,
        body=req.body,
        subject=req.subject,
        from_raw=req.from_addr,
        reply_to_raw=req.reply_to,
    )
    preview = req.subject or req.from_addr or req.raw_headers[:80] or "(email)"
    result = ScanResult(
        id=str(uuid.uuid4()),
        scan_type="email",
        risk_level=raw.risk_level,
        risk_score=raw.risk_score,
        summary=raw.summary,
        evidence=[_ev(e) for e in raw.evidence],
        next_steps=raw.next_steps,
        limitations=raw.limitations,
        created_at=now_iso(),
        subject=raw.subject,
        from_addr=raw.from_addr,
        reply_to=raw.reply_to,
        auth_results=raw.auth_results,
        headers_parsed=raw.headers_parsed,
        extracted_urls=raw.extracted_urls,
    )
    save_scan("email", preview[:200], result)
    return result


# ── QR Code Analysis ───────────────────────────────────────────────────────
@router.post("/analyze/qr", response_model=ScanResult)
async def analyze_qr_endpoint(file: UploadFile = File(...)):
    # Validate content type
    allowed_types = {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/bmp", "image/gif"}
    if file.content_type and file.content_type.lower() not in allowed_types:
        raise HTTPException(
            400,
            f"Unsupported image type: {file.content_type}. Supported: PNG, JPEG, WEBP, BMP, GIF."
        )

    image_bytes = await file.read()
    if len(image_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(413, f"File too large. Maximum is {MAX_UPLOAD_SIZE // (1024*1024)} MB.")

    qr_raw = analyze_qr(image_bytes, file.filename or "upload")

    nested_verdict = qr_raw.verdict
    nested_risk_level = qr_raw.risk_level
    nested_risk_score = qr_raw.risk_score
    nested_confidence = qr_raw.confidence
    nested_summary = qr_raw.summary
    nested_evidence = [_ev(e) for e in qr_raw.evidence]
    nested_pos = []
    nested_neg = []
    nested_next_steps = qr_raw.next_steps
    nested_limitations = qr_raw.limitations
    nested_sources = ["QR Image Decoder (pyzbar)"]
    nested_completed = ["QR Matrix Decoding", f"Payload Classification ({qr_raw.qr_type})"]
    nested_unavailable = []
    nested_extracted_urls = []

    if qr_raw.decoded_text and qr_raw.decode_available:
        if qr_raw.qr_type == "url":
            url_raw = analyze_url(qr_raw.decoded_text)
            nested_verdict = url_raw.verdict
            nested_risk_level = url_raw.risk_level
            nested_risk_score = url_raw.risk_score
            nested_confidence = url_raw.confidence
            nested_summary = f"Decoded QR URL: {qr_raw.decoded_text[:100]}. {url_raw.summary}"
            nested_evidence = [_ev(e) for e in qr_raw.evidence] + [_ev(e) for e in url_raw.evidence]
            nested_pos = [_ev(e) for e in url_raw.positive_evidence]
            nested_neg = [_ev(e) for e in url_raw.negative_evidence]
            nested_next_steps = url_raw.next_steps
            nested_limitations = qr_raw.limitations + url_raw.limitations
            nested_sources += url_raw.sources_consulted
            nested_completed += url_raw.checks_completed
            nested_unavailable += url_raw.checks_unavailable
            nested_extracted_urls = [qr_raw.decoded_text]
        elif qr_raw.qr_type == "deep_link":
            nested_verdict = qr_raw.verdict
            nested_risk_level = qr_raw.risk_level
            nested_risk_score = qr_raw.risk_score
            nested_confidence = qr_raw.confidence
            nested_summary = qr_raw.summary
            nested_evidence = [_ev(e) for e in qr_raw.evidence]
            nested_pos = [_ev(e) for e in qr_raw.evidence if e.severity in ("safe", "info")]
            nested_next_steps = qr_raw.next_steps
        elif qr_raw.qr_type in ("wifi", "vcard", "upi_payment", "phone", "email", "sms"):
            nested_verdict = qr_raw.verdict
            nested_risk_level = qr_raw.risk_level
            nested_risk_score = qr_raw.risk_score
            nested_confidence = qr_raw.confidence
            nested_summary = qr_raw.summary
            nested_evidence = [_ev(e) for e in qr_raw.evidence]
            nested_neg = [_ev(e) for e in qr_raw.evidence if e.severity in ("critical", "high", "medium")]
            nested_pos = [_ev(e) for e in qr_raw.evidence if e.severity in ("safe", "info")]
            nested_next_steps = qr_raw.next_steps
        elif qr_raw.qr_type == "text":
            msg_raw = analyze_message(qr_raw.decoded_text)
            nested_verdict = "MALICIOUS" if msg_raw.risk_level in ("critical", "high") else "SUSPICIOUS" if msg_raw.risk_level == "medium" else "NO KNOWN THREAT FOUND"
            nested_risk_level = msg_raw.risk_level
            nested_risk_score = msg_raw.risk_score
            nested_summary = f"QR decoded to text: {msg_raw.summary}"
            nested_evidence = [_ev(e) for e in qr_raw.evidence] + [_ev(e) for e in msg_raw.evidence]
            nested_next_steps = msg_raw.next_steps
            nested_limitations = qr_raw.limitations + msg_raw.limitations
            nested_extracted_urls = msg_raw.extracted_urls
    else:
        # Decode failed or library unavailable
        nested_verdict = "UNKNOWN / UNABLE TO VERIFY"
        nested_risk_level = "low"
        nested_risk_score = 10
        nested_confidence = "low"
        nested_summary = qr_raw.error or "QR decode failed: no QR code found in the image."
        nested_evidence = [EvidenceOut(
            signal="QR decode unverified",
            severity="low",
            explanation=qr_raw.error or "No QR pattern detected in the image.",
            category="Scanner",
        )]
        nested_unavailable = ["QR Decode Engine (unreadable or missing QR pattern)"]

    result = ScanResult(
        id=str(uuid.uuid4()),
        scan_type="qr",
        risk_level=nested_risk_level,
        risk_score=nested_risk_score,
        verdict=nested_verdict,
        confidence=nested_confidence,
        summary=nested_summary,
        evidence=nested_evidence,
        positive_evidence=nested_pos,
        negative_evidence=nested_neg,
        sources_consulted=nested_sources,
        checks_completed=nested_completed,
        checks_unavailable=nested_unavailable,
        next_steps=nested_next_steps,
        limitations=nested_limitations + [
            "ScamShield does NOT automatically navigate to or execute decoded content.",
            "QR analysis relies on static image inspection.",
        ],
        created_at=now_iso(),
        decoded_text=qr_raw.decoded_text,
        qr_type=qr_raw.qr_type,
        file_sha256=qr_raw.file_sha256,
        decode_available=qr_raw.decode_available,
        extracted_urls=nested_extracted_urls,
    )
    save_scan("qr", qr_raw.decoded_text or "(qr decode unverified)", result)
    return result


# ── File Analysis ─────────────────────────────────────────────────────────
@router.post("/analyze/file", response_model=ScanResult)
async def analyze_file_endpoint(file: UploadFile = File(...)):
    file_bytes = await file.read()
    if len(file_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(413, f"File too large. Maximum is {MAX_UPLOAD_SIZE // (1024*1024)} MB.")
    if len(file_bytes) == 0:
        raise HTTPException(400, "Uploaded file is empty.")

    raw = analyze_file(file_bytes, file.filename or "upload")

    result = ScanResult(
        id=str(uuid.uuid4()),
        scan_type="file",
        risk_level=raw.risk_level,
        risk_score=raw.risk_score,
        summary=raw.summary,
        evidence=[_ev(e) for e in raw.evidence],
        next_steps=raw.next_steps,
        limitations=raw.limitations,
        created_at=now_iso(),
        filename=raw.filename,
        file_size_bytes=raw.file_size_bytes,
        file_sha256=raw.sha256,
        detected_type=raw.detected_type,
        claimed_extension=raw.claimed_extension,
        type_mismatch=raw.type_mismatch,
        archive_contents=raw.archive_contents,
        macro_detected=raw.macro_detected,
        embedded_urls=raw.embedded_urls,
    )
    save_scan("file", file.filename or "(unknown file)", result)
    return result


# ── History ────────────────────────────────────────────────────────────────
@router.get("/history", response_model=list[HistoryItem])
def get_history(limit: int = 50, scan_type: Optional[str] = None):
    limit = min(limit, 200)
    with get_db() as conn:
        if scan_type:
            rows = conn.execute(
                "SELECT id, scan_type, input_preview, risk_level, risk_score, summary, created_at "
                "FROM scan_history WHERE scan_type=? ORDER BY created_at DESC LIMIT ?",
                (scan_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, scan_type, input_preview, risk_level, risk_score, summary, created_at "
                "FROM scan_history ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


@router.get("/history/{scan_id}", response_model=ScanResult)
def get_scan_detail(scan_id: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT full_result FROM scan_history WHERE id=?", (scan_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found")
    return json.loads(row["full_result"])


@router.delete("/history")
def clear_history():
    with get_db() as conn:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
    return {"message": "History cleared"}


# ── Stats ──────────────────────────────────────────────────────────────────
@router.get("/stats")
def get_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0] or 0
        critical = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='critical'").fetchone()[0] or 0
        high = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='high'").fetchone()[0] or 0
        medium = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='medium'").fetchone()[0] or 0
        low = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='low'").fetchone()[0] or 0
        safe = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='safe'").fetchone()[0] or 0
        avg_row = conn.execute("SELECT AVG(risk_score) FROM scan_history").fetchone()[0]
        avg_score = round(avg_row or 0, 1) if avg_row is not None else 0.0

        unique_urls = conn.execute("SELECT COUNT(DISTINCT input_preview) FROM scan_history WHERE scan_type='url'").fetchone()[0] or 0

        by_type_rows = conn.execute(
            "SELECT scan_type, COUNT(*) as cnt FROM scan_history GROUP BY scan_type"
        ).fetchall()
        by_type = {r["scan_type"]: r["cnt"] for r in by_type_rows}

        recent_critical = conn.execute(
            "SELECT id, scan_type, input_preview, risk_level, risk_score, summary, created_at "
            "FROM scan_history WHERE risk_level='critical' ORDER BY created_at DESC LIMIT 5"
        ).fetchall()

        recent_all = conn.execute(
            "SELECT id, scan_type, input_preview, risk_level, risk_score, summary, created_at "
            "FROM scan_history ORDER BY created_at DESC LIMIT 5"
        ).fetchall()

    eval_summary = evaluate_dataset()

    return {
        "total_scans": total,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "safe_count": safe,
        "malicious_count": critical + high,
        "suspicious_count": medium,
        "no_known_threat_count": low + safe,
        "unique_urls_analyzed": unique_urls,
        "url_scans_count": by_type.get("url", 0),
        "qr_scans_count": by_type.get("qr", 0),
        "email_scans_count": by_type.get("email", 0),
        "file_scans_count": by_type.get("file", 0),
        "message_scans_count": by_type.get("message", 0),
        "average_risk_score": avg_score,
        "by_scan_type": by_type,
        "recent_critical": [dict(r) for r in recent_critical],
        "recent_scans": [dict(r) for r in recent_all],
        "threat_intel_providers": threat_intel_manager.get_provider_statuses(),
        "benchmark_evaluation": {
            "dataset_size": eval_summary["dataset_size"],
            "accuracy_pct": eval_summary["accuracy_pct"],
            "precision_pct": eval_summary["precision_pct"],
            "recall_pct": eval_summary["recall_pct"],
            "f1_score_pct": eval_summary["f1_score_pct"],
            "false_positives": eval_summary["false_positives"],
            "false_negatives": eval_summary["false_negatives"],
        },
        "measurement_timestamp": now_iso(),
    }


@router.get("/evaluation")
def get_evaluation():
    """Return full documented benchmark dataset evaluation with precision/recall and confusion matrix."""
    return evaluate_dataset()


# ── Demo / benchmark cases ─────────────────────────────────────────────────
DEMO_CASES = [
    {
        "id": "demo-1",
        "type": "url",
        "label": "scam",
        "input": "http://paypal-login-secure.tk/verify?account=suspended&redirect=http://evil.com",
        "expected_risk": "critical",
        "description": "Classic PayPal phishing with HTTP, free TLD, impersonation, open-redirect",
    },
    {
        "id": "demo-2",
        "type": "url",
        "label": "scam",
        "input": "http://192.168.1.1/admin/login",
        "expected_risk": "high",
        "description": "Raw IP address URL with credential path",
    },
    {
        "id": "demo-3",
        "type": "url",
        "label": "legitimate",
        "input": "https://www.google.com/search?q=python+tutorial",
        "expected_risk": "safe",
        "description": "Standard Google HTTPS URL",
    },
    {
        "id": "demo-4",
        "type": "url",
        "label": "legitimate",
        "input": "https://github.com/openai/whisper",
        "expected_risk": "safe",
        "description": "GitHub repository URL",
    },
    {
        "id": "demo-5",
        "type": "message",
        "label": "scam",
        "input": "URGENT: Your SBI account has been suspended. Verify your Aadhaar and OTP immediately at http://sbi-verify.tk/login or your account will be closed within 24 hours!",
        "expected_risk": "critical",
        "description": "SMS phishing: bank impersonation, urgency, OTP harvest, suspicious URL",
    },
    {
        "id": "demo-6",
        "type": "message",
        "label": "scam",
        "input": "Congratulations! You have won a prize of Rs 50,00,000 in the KBC lottery. Claim your reward now. Call 9XXXXXXXXX and keep this confidential. Do not share this with anyone.",
        "expected_risk": "critical",
        "description": "Lottery scam: prize claim, secrecy instruction, financial lure",
    },
    {
        "id": "demo-7",
        "type": "message",
        "label": "legitimate",
        "input": "Hi John, your Amazon order #112-3456789-1234567 for 'Wireless Headphones' has been shipped. Expected delivery: Thursday 14 Oct. Track at amazon.com/orders.",
        "expected_risk": "low",
        "description": "Legitimate Amazon shipping notification",
    },
    {
        "id": "demo-8",
        "type": "message",
        "label": "legitimate",
        "input": "Your OTP for login to NetBanking is 847291. Valid for 10 minutes. Do not share this OTP with anyone. - HDFCBK",
        "expected_risk": "medium",
        "description": "Genuine OTP message (OTP keyword triggers medium — users should still be cautious)",
    },
    {
        "id": "demo-9",
        "type": "message",
        "label": "scam",
        "input": "Exciting remote job opportunity! Work from home part-time and earn 5000 daily just by reviewing videos on YouTube. Join our Telegram recruiter now @quick_hire_hr to start.",
        "expected_risk": "high",
        "description": "Task/Part-time job fraud: unreal wage, Telegram diversion, review tasks",
    },
    {
        "id": "demo-10",
        "type": "message",
        "label": "scam",
        "input": "Exclusive USDT airdrop bonus! Connect wallet now and double your deposit with guaranteed 200% profit within 24 hours. Enter seed phrase at http://claim-airdrop-usdt.xyz/connect",
        "expected_risk": "critical",
        "description": "Web3/Crypto drainer: seed phrase request, guaranteed profit, suspicious TLD",
    },
]


@router.get("/demo-cases")
def get_demo_cases():
    return DEMO_CASES


@router.post("/demo-cases/{case_id}/run")
def run_demo_case(case_id: str):
    case = next((c for c in DEMO_CASES if c["id"] == case_id), None)
    if not case:
        raise HTTPException(404, "Demo case not found")

    if case["type"] == "url":
        raw = analyze_url(case["input"])
    else:
        raw = analyze_message(case["input"])

    return {
        "case": case,
        "risk_level": raw.risk_level,
        "risk_score": raw.risk_score,
        "matched_expected": raw.risk_level == case["expected_risk"],
        "evidence_count": len(raw.evidence),
    }


# ---------------------------------------------------------------------------
# Register routers
# ---------------------------------------------------------------------------
# Existing analysis routes
app.include_router(router)
app.include_router(router, prefix="/api")
app.include_router(router, prefix="/api/v1")

# Auth and admin routes
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(superadmin_router)
app.include_router(public_settings_router)

# Also under /api prefix
app.include_router(auth_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(superadmin_router, prefix="/api")
app.include_router(public_settings_router, prefix="/api")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"Starting ScamShield backend on http://{host}:{port} ...")
    uvicorn.run("main:app", host=host, port=port, reload=True)

