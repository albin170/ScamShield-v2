"""
File / Attachment Metadata Analyzer — ScamShield
Performs safe, static metadata analysis on uploaded files.

What it checks:
  - File type identification by magic bytes (not filename extension)
  - SHA-256 hash for threat-intel lookup reference
  - Suspicious double extensions
  - Executable / script / macro-enabled indicators
  - Archive metadata (without extraction — limits resource exhaustion)
  - Embedded URL patterns in plaintext files
  - File size checks

Security guarantees:
  - NO execution of uploaded files, macros, or scripts.
  - NO claim of malware detection without an actual AV engine.
  - All analysis is purely static metadata inspection.
  - Memory-bounded: max 25 MB per upload.
"""

import io
import re
import hashlib
import zipfile
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Magic byte signatures → type label
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES = [
    (b"\x50\x4b\x03\x04", "ZIP archive"),
    (b"\x50\x4b\x05\x06", "ZIP archive (empty)"),
    (b"\x50\x4b\x07\x08", "ZIP archive (spanned)"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Microsoft Office (OLE/CFB) — may contain macros"),
    (b"\x25\x50\x44\x46", "PDF document"),
    (b"\x4D\x5A", "Windows PE executable (EXE/DLL)"),
    (b"\x7f\x45\x4c\x46", "Linux ELF executable"),
    (b"\xCA\xFE\xBA\xBE", "Java class file"),
    (b"\x23\x21", "Script file (shebang)"),
    (b"\x52\x61\x72\x21", "RAR archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"\xFD\x37\x7A\x58\x5A\x00", "XZ/7-zip archive"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "7-Zip archive"),
    (b"\x49\x44\x33", "MP3 audio"),
    (b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x47\x49\x46\x38", "GIF image"),
    (b"\x42\x4d", "BMP image"),
    (b"\x4f\x54\x54\x4f", "OpenType font"),
    (b"\x00\x00\x00", "Binary data (unknown format)"),
]

# Extension groups
EXECUTABLE_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".com", ".msi", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".ps2", ".psm1", ".psd1", ".sh", ".bash",
    ".py", ".rb", ".pl", ".lua", ".app", ".deb", ".rpm", ".dmg", ".pkg",
    ".apk", ".ipa", ".run", ".bin",
}

MACRO_EXTS = {
    ".doc", ".docm", ".xls", ".xlsm", ".xlam", ".ppt", ".pptm",
    ".dotm", ".xltm", ".potm", ".xlsb",
}

OFFICE_EXTS = {
    ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
    ".odt", ".ods", ".odp", ".docm", ".xlsm", ".pptm",
}

ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz"}

SAFE_EXTS = {
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md", ".log",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg",
    ".mp3", ".mp4", ".wav", ".pdf",
}

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB

# Office XML paths that indicate macro content
MACRO_INDICATORS_IN_ZIP = [
    "xl/vbaProject.bin",    # Excel macro
    "word/vbaProject.bin",  # Word macro
    "ppt/vbaProject.bin",   # PowerPoint macro
    "xl/macrosheets/",
    "word/macros/",
]


@dataclass
class FileEvidence:
    signal: str
    severity: str
    explanation: str


@dataclass
class FileAnalysisResult:
    filename: str
    file_size_bytes: int
    sha256: str
    detected_type: str
    claimed_extension: str
    type_mismatch: bool
    risk_level: str
    risk_score: int
    evidence: list[FileEvidence] = field(default_factory=list)
    summary: str = ""
    next_steps: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    archive_contents: list[str] = field(default_factory=list)
    macro_detected: bool = False
    embedded_urls: list[str] = field(default_factory=list)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_type(data: bytes) -> str:
    for magic, label in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return label
    # Try text detection
    try:
        sample = data[:4096]
        sample.decode("utf-8")
        return "Plain text"
    except Exception:
        pass
    return "Unknown binary"


def _has_double_extension(name: str) -> tuple[bool, str]:
    """Returns (is_double_ext, detail_string)"""
    parts = name.lower().split(".")
    if len(parts) >= 3:
        inner = "." + parts[-2]
        outer = "." + parts[-1]
        if inner in EXECUTABLE_EXTS or inner in MACRO_EXTS:
            return True, f"'{inner}{outer}'"
    return False, ""


def _check_zip_contents(data: bytes) -> tuple[list[str], bool]:
    """List ZIP contents and detect macro-indicating files. Returns (names, has_macro)."""
    names = []
    has_macro = False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()[:50]  # Limit to first 50 entries
            for name in z.namelist():
                lower = name.lower()
                if any(ind in lower for ind in MACRO_INDICATORS_IN_ZIP):
                    has_macro = True
                    break
    except Exception:
        pass
    return names, has_macro


def _extract_urls_from_text(data: bytes) -> list[str]:
    try:
        text = data[:50000].decode("utf-8", errors="replace")
    except Exception:
        return []
    return re.findall(r"https?://[^\s<>\"']{5,}", text)[:20]


def analyze_file(file_bytes: bytes, filename: str) -> FileAnalysisResult:
    """
    Perform safe, static metadata analysis on an uploaded file.
    Does NOT execute, open, or run the file in any environment.
    """
    filename = Path(filename).name  # Sanitise filename — strip directory components
    ext = Path(filename.lower()).suffix
    file_size = len(file_bytes)
    sha256 = _sha256(file_bytes)

    evidence: list[FileEvidence] = []
    score = 0
    archive_contents: list[str] = []
    macro_detected = False
    embedded_urls: list[str] = []

    # ── 1. File size check ────────────────────────────────────────────────
    if file_size > MAX_FILE_SIZE:
        return FileAnalysisResult(
            filename=filename,
            file_size_bytes=file_size,
            sha256=sha256,
            detected_type="unknown",
            claimed_extension=ext,
            type_mismatch=False,
            risk_level="medium",
            risk_score=30,
            evidence=[FileEvidence("File too large", "medium",
                f"File exceeds the {MAX_FILE_SIZE // (1024*1024)} MB limit. Analysis was not performed.")],
            summary="File too large for analysis.",
            next_steps=["Do not open files from untrusted sources.", "Scan with reputable antivirus software."],
            limitations=["File was not analysed — size limit exceeded."],
        )

    detected_type = _detect_type(file_bytes)

    # ── 2. Type mismatch ──────────────────────────────────────────────────
    type_mismatch = False
    if ext in SAFE_EXTS and ("executable" in detected_type.lower() or "archive" in detected_type.lower()):
        type_mismatch = True
        score += 40
        evidence.append(FileEvidence(
            "File type mismatch",
            "critical",
            f"The file extension is '{ext}' (claiming to be {ext}) but its actual content is '{detected_type}'. "
            "Attackers rename executables or archives as safe files (e.g., 'invoice.pdf.exe' shown as 'invoice.pdf'). "
            "This is a strong indicator of malicious intent."
        ))

    # ── 3. Executable file ────────────────────────────────────────────────
    if ext in EXECUTABLE_EXTS:
        score += 55
        if "pe" in detected_type.lower() or "executable" in detected_type.lower() or "elf" in detected_type.lower():
            score += 20
        evidence.append(FileEvidence(
            f"Executable file type: {ext}",
            "critical",
            f"This file has an executable extension ({ext}). Running this file on your computer can execute arbitrary code. "
            "Never run executable attachments from unknown or unsolicited sources."
        ))
    elif "executable" in detected_type.lower() or "elf" in detected_type.lower() or "pe" in detected_type.lower():
        if ext not in EXECUTABLE_EXTS:
            score += 55
            evidence.append(FileEvidence(
                "Hidden executable content",
                "critical",
                f"This file appears to be an executable program based on its binary signature ({detected_type}), "
                f"despite having a '{ext}' extension. This is a common malware delivery technique."
            ))

    # ── 4. Macro-enabled documents ────────────────────────────────────────
    if ext in MACRO_EXTS:
        score += 30
        evidence.append(FileEvidence(
            f"Macro-capable document type: {ext}",
            "high",
            f"Files with '{ext}' extension can contain VBA macros that execute code when opened. "
            "Attackers frequently use macro-enabled Office documents to install malware. "
            "Do not enable macros unless you trust the source explicitly."
        ))

    # ── 5. Archive contents ───────────────────────────────────────────────
    if "zip" in detected_type.lower() or ext in ARCHIVE_EXTS:
        if ext in (".zip", "") or "zip" in detected_type.lower():
            archive_contents, has_macro = _check_zip_contents(file_bytes)
            if has_macro:
                macro_detected = True
                score += 35
                evidence.append(FileEvidence(
                    "Macro content inside archive",
                    "critical",
                    "The ZIP archive contains Office VBA macro files (vbaProject.bin). "
                    "This is a common way to deliver macro malware while bypassing email filters."
                ))

            exec_inside = [n for n in archive_contents if Path(n.lower()).suffix in EXECUTABLE_EXTS]
            if exec_inside:
                score += 30
                evidence.append(FileEvidence(
                    f"Executable files inside archive: {', '.join(exec_inside[:5])}",
                    "high",
                    "The archive contains executable files. Never run executables extracted from archives received from unknown sources."
                ))

        else:
            evidence.append(FileEvidence(
                f"Archive file: {ext}",
                "low",
                f"This is a compressed archive ({ext}). Be cautious when extracting — inspect the contents before opening any files inside."
            ))

    # ── 6. Double extension ───────────────────────────────────────────────
    is_double, double_detail = _has_double_extension(filename)
    if is_double:
        score += 30
        evidence.append(FileEvidence(
            f"Suspicious double extension: {double_detail}",
            "critical",
            f"The filename '{filename}' uses a double extension. The inner extension {double_detail.split('.')[1] if '.' in double_detail else ''} "
            "may indicate the real file type. Windows hides known extensions by default, making this a common trick to disguise malicious files."
        ))

    # ── 7. Script shebang ─────────────────────────────────────────────────
    if detected_type == "Script file (shebang)":
        score += 25
        evidence.append(FileEvidence(
            "Script file (shebang detected)",
            "high",
            "This file starts with a shebang (#!) indicating it is a script. Running it could execute arbitrary commands on your system."
        ))

    # ── 8. URLs embedded in plain text ───────────────────────────────────
    if "text" in detected_type.lower() or ext in (".txt", ".csv", ".log", ".md"):
        embedded_urls = _extract_urls_from_text(file_bytes)
        if embedded_urls:
            evidence.append(FileEvidence(
                f"URLs found in file ({len(embedded_urls)} links)",
                "low",
                "The file contains embedded URLs. These should be individually analysed using the URL scanner before visiting."
            ))

    # ── 9. Large file without apparent purpose ───────────────────────────
    if file_size > 5 * 1024 * 1024 and ext in SAFE_EXTS and "image" not in detected_type.lower():
        score += 10
        evidence.append(FileEvidence(
            f"Unexpectedly large file: {file_size // (1024*1024)} MB",
            "low",
            f"A {ext} file of {file_size // (1024*1024)} MB is unusually large. Large files may contain hidden payloads or padding to disguise content."
        ))

    # ── Positive signals ──────────────────────────────────────────────────
    if ext in SAFE_EXTS and not type_mismatch and not is_double:
        evidence.append(FileEvidence(
            f"File type appears consistent: {ext}",
            "safe",
            f"The file extension ({ext}) is consistent with its detected content type ({detected_type}). "
            "This does not guarantee safety — always verify the sender and context."
        ))

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
        "critical": f"This file has critical risk indicators. Do NOT open, run, or extract it without professional security review. Score: {score}/100.",
        "high": f"This file has significant warning signs. Exercise extreme caution. Score: {score}/100.",
        "medium": f"This file has some suspicious characteristics. Verify the sender before opening. Score: {score}/100.",
        "low": f"This file has minor concerns. Confirm the sender's identity. Score: {score}/100.",
        "safe": f"No significant risk indicators found in static metadata. Score: {score}/100.",
    }

    steps_map = {
        "critical": [
            "Do NOT open, run, or extract this file.",
            "Delete it and empty your recycle bin.",
            "Report to your IT department or cybersecurity contact.",
            "Scan with reputable antivirus software in a sandboxed environment if analysis is required.",
        ],
        "high": [
            "Do not open this file without verifying the sender through an independent channel.",
            "Scan with antivirus software before opening.",
            "If in doubt, contact the sender via a known phone number to confirm they sent it.",
        ],
        "medium": [
            "Verify the sender's identity before opening.",
            "Scan with antivirus software.",
            "Treat all macros and executable content as untrusted.",
        ],
        "low": [
            "Confirm the sender before opening.",
            "Keep your system and antivirus software up to date.",
        ],
        "safe": [
            "Continue exercising caution with all attachments.",
            "Even safe-looking files can contain malicious content if the sender is compromised.",
        ],
    }

    limitations = [
        "ScamShield performs STATIC METADATA ANALYSIS ONLY. It does NOT scan for viruses, malware, or ransomware.",
        "A 'safe' result here does NOT mean the file is free of malware.",
        "For definitive malware analysis, scan with reputable antivirus software or use services like VirusTotal.",
        "Encrypted archives cannot have their contents inspected.",
        "Obfuscated scripts may not be detectable through metadata alone.",
    ]

    return FileAnalysisResult(
        filename=filename,
        file_size_bytes=file_size,
        sha256=sha256,
        detected_type=detected_type,
        claimed_extension=ext,
        type_mismatch=type_mismatch,
        risk_level=risk_level,
        risk_score=score,
        evidence=evidence,
        summary=summary_map[risk_level],
        next_steps=steps_map[risk_level],
        limitations=limitations,
        archive_contents=archive_contents,
        macro_detected=macro_detected,
        embedded_urls=embedded_urls,
    )
