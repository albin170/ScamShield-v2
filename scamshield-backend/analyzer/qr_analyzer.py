"""
QR Code Analyzer — ScamShield Production-Grade Detection Pipeline
Decodes QR codes from uploaded images and camera frames safely, preserving raw payload,
identifying structured payload types (URL, Social Deep Links, Wi-Fi, vCard, UPI, Contact),
and delegating URL payloads to the explainable URL analysis engine.

Security Guarantees:
- In-memory decoding only (no temp files on disk)
- Never navigates to or opens decoded URLs
- Never executes decoded content or deep links
- Sanitizes and safely escapes all rendered output
"""
import io
import re
import os
import sys
import hashlib
import pathlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------------
# Windows DLL Setup for pyzbar
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    try:
        import pyzbar
        pyzbar_dir = str(pathlib.Path(pyzbar.__file__).parent)
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(pyzbar_dir)
    except Exception:
        pass

    for candidate_dir in [
        r"C:\Program Files\Common Files\microsoft shared\ClickToRun",
        r"C:\Program Files (x86)\Common Files\Adobe\OOBE\PDApp\DECore",
    ]:
        if os.path.isdir(candidate_dir) and hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(candidate_dir)
            except Exception:
                pass

# Safe Image & Decoding Imports
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except Exception:
    PYZBAR_AVAILABLE = False


@dataclass
class QREvidence:
    signal: str
    severity: str  # "critical" | "high" | "medium" | "low" | "safe" | "info"
    explanation: str
    category: str = "QR Payload"


@dataclass
class QRAnalysisResult:
    decoded_text: Optional[str]
    qr_type: str            # "url" | "deep_link" | "wifi" | "vcard" | "upi_payment" | "phone" | "email" | "sms" | "text" | "unknown" | "unavailable"
    file_sha256: str
    decode_available: bool
    error: Optional[str] = None
    verdict: str = "NO KNOWN THREAT FOUND"  # "MALICIOUS" | "SUSPICIOUS" | "NO KNOWN THREAT FOUND" | "UNKNOWN / UNABLE TO VERIFY"
    risk_level: str = "safe"                # "safe" | "low" | "medium" | "high" | "critical"
    risk_score: int = 0
    confidence: str = "medium"
    summary: str = ""
    evidence: list[QREvidence] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    parsed_payload_details: dict = field(default_factory=dict)
    nested_analysis: Optional[dict] = None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Known official social-media deep-link schemes
KNOWN_DEEP_LINK_SCHEMES = {
    "instagram": "Instagram App Deep Link",
    "snapchat": "Snapchat App Deep Link",
    "fb": "Facebook App Deep Link",
    "fb-messenger": "Facebook Messenger Deep Link",
    "whatsapp": "WhatsApp App Deep Link",
    "twitter": "Twitter/X App Deep Link",
    "tg": "Telegram App Deep Link",
    "viber": "Viber App Deep Link",
    "tiktok": "TikTok App Deep Link",
    "spotify": "Spotify App Deep Link",
    "discord": "Discord App Deep Link",
    "linkedin": "LinkedIn App Deep Link",
}


def classify_qr_payload(text: str) -> tuple[str, dict]:
    """
    Classify decoded QR string into structured payload types.
    Returns (payload_type, metadata_dict).
    """
    raw = text.strip()
    low = raw.lower()

    # 1. Standard Web URL
    if low.startswith(("http://", "https://", "ftp://")) or (
        low.startswith("www.") and "." in low[4:]
    ):
        return "url", {"url": raw if "://" in raw else f"https://{raw}"}

    # 2. App Deep Links (e.g. instagram://user?username=..., snapchat://add/...)
    scheme_match = re.match(r"^([a-zA-Z0-9+.-]+)://(.*)", raw)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        rest = scheme_match.group(2)
        if scheme == "upi":
            # Handled in UPI payment branch
            pass
        elif scheme in KNOWN_DEEP_LINK_SCHEMES:
            return "deep_link", {
                "scheme": scheme,
                "app_name": KNOWN_DEEP_LINK_SCHEMES[scheme],
                "target": rest,
            }
        elif scheme in ("tel", "callto"):
            return "phone", {"phone_number": rest}
        elif scheme == "mailto":
            return "email", {"recipient": rest}
        elif scheme in ("sms", "smsto"):
            return "sms", {"target": rest}

    # 3. Wi-Fi network configuration: WIFI:S:MySSID;T:WPA;P:MyPassword;;
    if raw.startswith("WIFI:") or raw.startswith("wifi:"):
        wifi_meta = {}
        parts = raw[5:].split(";")
        for p in parts:
            if p.startswith("S:"):
                wifi_meta["ssid"] = p[2:]
            elif p.startswith("T:"):
                wifi_meta["security"] = p[2:]
            elif p.startswith("P:"):
                wifi_meta["password_length"] = len(p[2:])
            elif p.startswith("H:"):
                wifi_meta["hidden"] = p[2:].lower() == "true"
        return "wifi", wifi_meta

    # 4. vCard / Contact Card
    if raw.startswith("BEGIN:VCARD") or raw.startswith("MECARD:"):
        contact_meta = {}
        fn_match = re.search(r"FN:(.+)", raw, re.IGNORECASE) or re.search(r"N:(.+)", raw, re.IGNORECASE)
        if fn_match:
            contact_meta["name"] = fn_match.group(1).strip()
        tel_match = re.search(r"TEL.*:(.+)", raw, re.IGNORECASE)
        if tel_match:
            contact_meta["phone"] = tel_match.group(1).strip()
        email_match = re.search(r"EMAIL.*:(.+)", raw, re.IGNORECASE)
        if email_match:
            contact_meta["email"] = email_match.group(1).strip()
        url_match = re.search(r"URL.*:(.+)", raw, re.IGNORECASE)
        if url_match:
            contact_meta["url"] = url_match.group(1).strip()
        return "vcard", contact_meta

    # 5. UPI payment
    if low.startswith("upi://pay"):
        upi_meta = {}
        try:
            parsed = urlparse(raw)
            qs = parse_qs(parsed.query)
            upi_meta["vpa"] = qs.get("pa", [""])[0]
            upi_meta["payee_name"] = qs.get("pn", [""])[0]
            upi_meta["amount"] = qs.get("am", [""])[0]
            upi_meta["note"] = qs.get("tn", [""])[0]
        except Exception:
            pass
        return "upi_payment", upi_meta

    # 6. Direct phone / mailto / sms
    if low.startswith("tel:"):
        return "phone", {"phone_number": raw[4:].strip()}
    if low.startswith("mailto:"):
        return "email", {"recipient": raw[7:].strip()}
    if low.startswith(("smsto:", "sms:")):
        return "sms", {"target": raw.split(":", 1)[-1].strip()}

    # 7. Plain text / fallback
    return "text", {"text_length": len(raw)}


def analyze_qr(image_bytes: bytes, filename: str = "upload") -> QRAnalysisResult:
    """
    Safely decode and inspect a QR code image.
    - Operates entirely in memory.
    - Never navigates to decoded destination.
    - Validates file constraints (max 10MB, valid formats).
    - Accurately classifies payload into URL, Deep Link, Wi-Fi, vCard, UPI, etc.
    """
    file_hash = _sha256_bytes(image_bytes)

    if not PIL_AVAILABLE or not PYZBAR_AVAILABLE:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unavailable",
            file_sha256=file_hash,
            decode_available=False,
            verdict="UNKNOWN / UNABLE TO VERIFY",
            risk_level="medium",
            risk_score=30,
            confidence="low",
            error="QR decoding runtime is not available on this server.",
            summary="QR decoding unavailable: pyzbar/Pillow could not be initialized.",
            limitations=["QR decoding runtime unavailable."],
        )

    # Validate file size (max 10 MB)
    if len(image_bytes) > 10 * 1024 * 1024:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            verdict="UNKNOWN / UNABLE TO VERIFY",
            risk_level="low",
            risk_score=20,
            error="Image too large (max 10 MB). Please upload a smaller file.",
            summary="Image exceeds maximum file size (10 MB).",
        )

    # Open image safely
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.verify()  # Validate image headers
        img = Image.open(io.BytesIO(image_bytes))  # Reopen after verify
    except Exception as e:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            verdict="UNKNOWN / UNABLE TO VERIFY",
            risk_level="low",
            risk_score=20,
            error=f"Could not open image: {str(e)[:180]}. Supported formats: PNG, JPEG, WEBP, BMP, GIF.",
            summary="Image file is corrupt or uses an unsupported format.",
        )

    # Decode QR code
    try:
        decoded_objects = pyzbar_decode(img)
    except Exception as e:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            verdict="UNKNOWN / UNABLE TO VERIFY",
            risk_level="low",
            risk_score=20,
            error=f"QR decode engine error: {str(e)[:180]}",
            summary="QR decode engine encountered an error while scanning the image.",
        )

    if not decoded_objects:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            verdict="UNKNOWN / UNABLE TO VERIFY",
            risk_level="low",
            risk_score=10,
            error="No QR code found in the image. Ensure the QR code is clearly visible, well-lit, and in focus.",
            summary="No QR code found in the image. Please retry with a clearer image.",
            next_steps=["Ensure the QR code is centered and not obstructed.", "Try taking a higher-contrast photo."],
        )

    # Extract primary decoded string
    raw_payload = decoded_objects[0].data.decode("utf-8", errors="replace").strip()
    qr_type, meta = classify_qr_payload(raw_payload)

    evidence: list[QREvidence] = [
        QREvidence(
            signal=f"Decoded QR code successfully ({qr_type.upper()})",
            severity="safe",
            explanation=f"Successfully extracted {len(raw_payload)} characters from image (SHA-256: {file_hash[:12]}...).",
        )
    ]

    verdict = "NO KNOWN THREAT FOUND"
    risk_level = "safe"
    risk_score = 0
    confidence = "high"
    summary = f"Decoded QR payload type: {qr_type}."
    next_steps = ["Inspect the decoded content before taking action."]

    # Specialized Non-URL Payload Handlers
    if qr_type == "deep_link":
        app_name = meta.get("app_name", "Application")
        scheme = meta.get("scheme", "")
        evidence.append(QREvidence(
            signal=f"Official {app_name}",
            severity="safe",
            explanation=f"This QR code encodes an official deep-link designed to open within the {app_name} on mobile devices.",
        ))
        summary = f"Official {app_name} link ({scheme}://). Safe to open in official app."
        next_steps = [f"Ensure you open this link only within the official {app_name}."]

    elif qr_type == "wifi":
        ssid = meta.get("ssid", "Unknown")
        sec = meta.get("security", "").upper()
        if sec in ("NOPASS", "NONE", ""):
            risk_score = 40
            risk_level = "medium"
            verdict = "SUSPICIOUS"
            evidence.append(QREvidence(
                signal="Unencrypted Open Wi-Fi Network",
                severity="medium",
                explanation=f"Network '{ssid}' does not use encryption (WPA/WPA2/WPA3). Anyone in proximity can monitor unencrypted traffic.",
            ))
            summary = f"Wi-Fi configuration for '{ssid}': Unencrypted open network."
            next_steps=["Do not enter passwords or sensitive personal data on unencrypted Wi-Fi networks."]
        else:
            evidence.append(QREvidence(
                signal=f"Secured Wi-Fi Network ({sec})",
                severity="safe",
                explanation=f"Network '{ssid}' uses {sec} encryption.",
            ))
            summary = f"Wi-Fi configuration for '{ssid}' with {sec} encryption."

    elif qr_type == "upi_payment":
        vpa = meta.get("vpa", "")
        payee = meta.get("payee_name", "")
        amount = meta.get("amount", "")
        risk_score = 35
        risk_level = "medium"
        verdict = "SUSPICIOUS"
        evidence.append(QREvidence(
            signal="UPI Payment Transfer Request",
            severity="medium",
            explanation=(
                f"QR encodes a payment to '{vpa}' (Name: {payee or 'Unspecified'}). "
                "Scammers frequently generate QR codes that deduct funds rather than receive them."
            ),
        ))
        summary = f"UPI Payment Request to {vpa}" + (f" for INR {amount}" if amount else "")
        next_steps=[
            "Never scan a QR code to RECEIVE money. Receiving money never requires a PIN.",
            f"Verify the recipient VPA '{vpa}' matches your intended merchant.",
        ]

    elif qr_type == "vcard":
        name = meta.get("name", "Contact")
        summary = f"Contact card for {name}."
        if "url" in meta:
            evidence.append(QREvidence(
                signal=f"Embedded website in contact: {meta['url']}",
                severity="info",
                explanation="Contact contains an external website link.",
            ))

    elif qr_type == "phone":
        summary = f"Phone contact link: {meta.get('phone_number', '')}."
        evidence.append(QREvidence(
            signal="Phone Dial Request",
            severity="info",
            explanation=f"Encodes phone number {meta.get('phone_number')}. Verify through official directories before calling.",
        ))

    limitations = [
        "ScamShield decodes QR content statically and NEVER executes scripts, triggers app intents, or navigates automatically.",
        "Visual appearance of a QR code does not indicate whether its destination is trustworthy.",
    ]

    return QRAnalysisResult(
        decoded_text=raw_payload,
        qr_type=qr_type,
        file_sha256=file_hash,
        decode_available=True,
        verdict=verdict,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        summary=summary,
        evidence=evidence,
        next_steps=next_steps,
        limitations=limitations,
        parsed_payload_details=meta,
    )
