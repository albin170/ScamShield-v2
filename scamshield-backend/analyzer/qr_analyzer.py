"""
QR Code Analyzer — ScamShield
Decodes QR codes from uploaded images and passes the decoded content
through the existing URL / message analysis pipeline.

Dependencies:
  pip install pillow pyzbar

If pyzbar is unavailable, falls back to a graceful unavailable state.
"""

import io
import hashlib
from dataclasses import dataclass, field
from typing import Optional

# Optional imports — graceful fallback if not installed
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except Exception:
    # On Windows, pyzbar raises FileNotFoundError when libzbar-64.dll is missing.
    # Graceful fallback: QR analysis will return an "unavailable" state.
    PYZBAR_AVAILABLE = False


@dataclass
class QRAnalysisResult:
    decoded_text: Optional[str]
    qr_type: str            # "url" | "text" | "unknown" | "unavailable"
    file_sha256: str
    decode_available: bool
    error: Optional[str] = None
    # Set by main.py after calling URL/message analyzer
    nested_analysis: Optional[dict] = None


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def analyze_qr(image_bytes: bytes, filename: str = "upload") -> QRAnalysisResult:
    """
    Decode a QR code image and return the decoded text plus metadata.
    The caller is responsible for passing the decoded_text to the URL or
    message analyzer if needed.

    Security notes:
    - We never navigate to the decoded URL.
    - We never execute decoded content.
    - File is kept entirely in memory.
    """
    file_hash = _sha256_bytes(image_bytes)

    if not PIL_AVAILABLE or not PYZBAR_AVAILABLE:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unavailable",
            file_sha256=file_hash,
            decode_available=False,
            error=(
                "QR decoding libraries are not installed on this server. "
                "Install them with: pip install pillow pyzbar\n"
                "On Linux you may also need: apt install libzbar0"
            ),
        )

    # Validate file size (max 10 MB)
    if len(image_bytes) > 10 * 1024 * 1024:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            error="Image too large (max 10 MB). Please upload a smaller file.",
        )

    # Open image safely
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.verify()  # Verify it's a valid image (raises if corrupt)
        img = Image.open(io.BytesIO(image_bytes))  # Re-open after verify
    except Exception as e:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            error=f"Could not open image: {str(e)[:200]}. Supported formats: PNG, JPEG, WEBP, BMP, GIF.",
        )

    # Decode QR
    try:
        decoded_objects = pyzbar_decode(img)
    except Exception as e:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            error=f"QR decode error: {str(e)[:200]}",
        )

    if not decoded_objects:
        return QRAnalysisResult(
            decoded_text=None,
            qr_type="unknown",
            file_sha256=file_hash,
            decode_available=True,
            error="No QR code found in the image. Make sure the QR code is clearly visible and not blurred.",
        )

    # Take first decoded object
    obj = decoded_objects[0]
    decoded_text = obj.data.decode("utf-8", errors="replace").strip()

    # Determine content type
    if decoded_text.lower().startswith(("http://", "https://", "www.")):
        qr_type = "url"
    elif decoded_text.lower().startswith("tel:"):
        qr_type = "phone"
    elif decoded_text.lower().startswith("mailto:"):
        qr_type = "email"
    elif decoded_text.lower().startswith("upi://"):
        qr_type = "upi_payment"
    else:
        qr_type = "text"

    return QRAnalysisResult(
        decoded_text=decoded_text,
        qr_type=qr_type,
        file_sha256=file_hash,
        decode_available=True,
        error=None,
    )
