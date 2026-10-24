"""
ScamShield Admin Routes — v3.0
Provides:
  /auth/*       — login, logout, me, change-password
  /admin/*      — admin-level operations (require admin or superadmin)
  /superadmin/* — full super admin panel (require superadmin only)
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Response, Request, Depends, status
from pydantic import BaseModel, field_validator

from auth import (
    hash_password, verify_password, create_access_token,
    require_auth, require_admin, require_superadmin,
    ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_USER,
    ALL_PERMISSIONS, DEFAULT_ADMIN_PERMISSIONS, has_permission,
)
from database import get_db

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _log_audit(conn, actor_id, actor_username, action, target_type=None,
               target_id=None, outcome="success", metadata=None, ip_address=None):
    conn.execute(
        """INSERT INTO audit_log
           (id, actor_id, actor_username, action, target_type, target_id, outcome, metadata, ip_address, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()), actor_id, actor_username, action,
            target_type, target_id, outcome,
            json.dumps(metadata or {}), ip_address, now_iso(),
        ),
    )


def _create_notification(conn, user_id, title, message, notif_type="info"):
    conn.execute(
        "INSERT INTO notifications (id, user_id, title, message, type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), user_id, title, message, notif_type, now_iso()),
    )


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Field must not be empty")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class CreateAdminRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    permissions: Optional[List[str]] = None

    @field_validator("username")
    @classmethod
    def valid_username(cls, v):
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username can only contain letters, numbers, hyphens, underscores")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UpdateAdminRequest(BaseModel):
    email: Optional[str] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_suspended: Optional[bool] = None


class UpdateThemeRequest(BaseModel):
    active_theme: Optional[str] = None
    neon_glow_intensity: Optional[float] = None
    bg_overlay_strength: Optional[float] = None
    animation_intensity: Optional[float] = None


class UpdateIntegrationsRequest(BaseModel):
    virustotal: Optional[dict] = None
    safebrowsing: Optional[dict] = None
    abuseipdb: Optional[dict] = None
    threatfox: Optional[dict] = None
    webhook_alerts: Optional[dict] = None


class UpdateFeaturesRequest(BaseModel):
    rate_limiting: Optional[bool] = None
    public_scans: Optional[bool] = None
    debug_logging: Optional[bool] = None
    audit_retention_days: Optional[int] = None
    deep_analysis_timeout_sec: Optional[int] = None



# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
auth_router = APIRouter(prefix="/auth", tags=["Auth"])
admin_router = APIRouter(prefix="/admin", tags=["Admin"])
superadmin_router = APIRouter(prefix="/superadmin", tags=["Super Admin"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


# ── Auth ──────────────────────────────────────────────────────────────────

@auth_router.post("/login")
def login(req: LoginRequest, response: Response, request: Request):
    """Authenticate and return an HttpOnly cookie with a JWT."""
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (req.username,)
        ).fetchone()

        if not user:
            _log_audit(conn, None, req.username, "login_failed", outcome="failure",
                       metadata={"reason": "user_not_found"},
                       ip_address=request.client.host if request.client else None)
            conn.commit()
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        user = dict(user)

        # Lockout check
        failed = user.get("failed_login_count", 0)
        last_fail_str = user.get("last_failed_login_at")
        if failed >= MAX_FAILED_ATTEMPTS and last_fail_str:
            last_fail = datetime.fromisoformat(last_fail_str)
            if datetime.now(timezone.utc) - last_fail < timedelta(minutes=LOCKOUT_MINUTES):
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.",
                )
            else:
                # Reset after lockout period
                conn.execute("UPDATE users SET failed_login_count=0 WHERE id=?", (user["id"],))

        if not user["is_active"] or user["is_suspended"]:
            raise HTTPException(status_code=403, detail="Account is suspended or inactive.")

        if not verify_password(req.password, user["password_hash"]):
            new_count = user.get("failed_login_count", 0) + 1
            conn.execute(
                "UPDATE users SET failed_login_count=?, last_failed_login_at=? WHERE id=?",
                (new_count, now_iso(), user["id"]),
            )
            _log_audit(conn, user["id"], user["username"], "login_failed", outcome="failure",
                       metadata={"reason": "wrong_password", "attempt": new_count},
                       ip_address=request.client.host if request.client else None)
            conn.commit()
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        # Success — reset fail count
        conn.execute(
            "UPDATE users SET failed_login_count=0, last_login_at=? WHERE id=?",
            (now_iso(), user["id"]),
        )
        _log_audit(conn, user["id"], user["username"], "login",
                   ip_address=request.client.host if request.client else None)
        conn.commit()

    perms = json.loads(user["permissions"]) if user["permissions"] else []
    token = create_access_token({
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "permissions": perms,
        "must_change_password": bool(user["must_change_password"]),
    })

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set True in HTTPS/production
        max_age=60 * 60 * 8,  # 8 hours
    )

    return {
        "message": "Login successful.",
        "username": user["username"],
        "role": user["role"],
        "must_change_password": bool(user["must_change_password"]),
        "permissions": perms,
    }


@auth_router.post("/logout")
def logout(response: Response, user=Depends(require_auth)):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully."}


@auth_router.get("/me")
def get_me(user=Depends(require_auth)):
    return {
        "id": user.get("sub"),
        "username": user.get("username"),
        "role": user.get("role"),
        "permissions": user.get("permissions", []),
        "must_change_password": user.get("must_change_password", False),
    }


@auth_router.post("/change-password")
def change_password(req: ChangePasswordRequest, user=Depends(require_auth)):
    with get_db() as conn:
        db_user = conn.execute(
            "SELECT password_hash FROM users WHERE id=?", (user["sub"],)
        ).fetchone()
        if not db_user:
            raise HTTPException(404, "User not found.")
        if not verify_password(req.current_password, db_user["password_hash"]):
            raise HTTPException(401, "Current password is incorrect.")
        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=0, updated_at=? WHERE id=?",
            (hash_password(req.new_password), now_iso(), user["sub"]),
        )
        _log_audit(conn, user["sub"], user.get("username"), "change_password")
        conn.commit()
    return {"message": "Password changed successfully."}


# ── Admin ─────────────────────────────────────────────────────────────────

@admin_router.get("/dashboard-stats")
def admin_dashboard_stats(user=Depends(require_admin)):
    with get_db() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        critical_count = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level='critical'").fetchone()[0]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_scans = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE created_at LIKE ?", (f"{today}%",)
        ).fetchone()[0]
        total_admins = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role IN ('admin','superadmin') AND is_active=1"
        ).fetchone()[0]
        login_events = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='login' AND created_at LIKE ?",
            (f"{today}%",),
        ).fetchone()[0]
        failed_logins = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='login_failed' AND created_at LIKE ?",
            (f"{today}%",),
        ).fetchone()[0]

    return {
        "total_scans": total_scans,
        "critical_count": critical_count,
        "today_scans": today_scans,
        "total_admins": total_admins,
        "today_login_events": login_events,
        "today_failed_logins": failed_logins,
    }


@admin_router.get("/profile")
def get_admin_profile(user=Depends(require_admin)):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, permissions, is_active, created_at, last_login_at FROM users WHERE id=?",
            (user["sub"],),
        ).fetchone()
    if not row:
        raise HTTPException(404, "User not found.")
    d = dict(row)
    d["permissions"] = json.loads(d["permissions"]) if d["permissions"] else []
    return d


@admin_router.get("/notifications")
def get_notifications(user=Depends(require_admin)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
            (user["sub"],),
        ).fetchall()
    return [dict(r) for r in rows]


@admin_router.post("/notifications/{notif_id}/read")
def mark_notification_read(notif_id: str, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute(
            "UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
            (notif_id, user["sub"]),
        )
        conn.commit()
    return {"message": "Marked as read."}


# ── Super Admin ───────────────────────────────────────────────────────────

@superadmin_router.get("/stats")
def superadmin_stats(user=Depends(require_superadmin)):
    with get_db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_active=1 AND is_suspended=0").fetchone()[0]
        suspended_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_suspended=1").fetchone()[0]
        total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        total_audit = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        unread_notifications = conn.execute("SELECT COUNT(*) FROM notifications WHERE is_read=0").fetchone()[0]
        db_size = conn.execute("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").fetchone()[0]

        # Scan by type
        scan_types = conn.execute(
            "SELECT scan_type, COUNT(*) as cnt FROM scan_history GROUP BY scan_type"
        ).fetchall()

        # Login events last 7 days
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        login_events_7d = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='login' AND created_at >= ?", (week_ago,)
        ).fetchone()[0]
        failed_7d = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action='login_failed' AND created_at >= ?", (week_ago,)
        ).fetchone()[0]

        # Risk breakdown
        by_risk = conn.execute(
            "SELECT risk_level, COUNT(*) as cnt FROM scan_history GROUP BY risk_level"
        ).fetchall()

    return {
        "users": {"total": total_users, "active": active_users, "suspended": suspended_users},
        "scans": {"total": total_scans, "by_type": {r["scan_type"]: r["cnt"] for r in scan_types},
                  "by_risk": {r["risk_level"]: r["cnt"] for r in by_risk}},
        "audit": {"total_events": total_audit},
        "notifications": {"unread": unread_notifications},
        "database": {"size_bytes": db_size},
        "logins": {"last_7d": login_events_7d, "failed_7d": failed_7d},
    }


@superadmin_router.get("/users")
def list_users(user=Depends(require_superadmin)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, email, role, permissions, is_active, is_suspended, must_change_password, created_at, last_login_at, created_by FROM users ORDER BY created_at DESC"
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["permissions"] = json.loads(d["permissions"]) if d["permissions"] else []
        result.append(d)
    return result


@superadmin_router.post("/users")
def create_admin_user(req: CreateAdminRequest, request: Request, user=Depends(require_superadmin)):
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (req.username,)).fetchone()
        if existing:
            raise HTTPException(400, f"Username '{req.username}' already exists.")

        new_id = str(uuid.uuid4())
        now = now_iso()
        perms = req.permissions if req.permissions is not None else DEFAULT_ADMIN_PERMISSIONS
        # Sanitize permissions — only allow known permissions
        perms = [p for p in perms if p in ALL_PERMISSIONS]

        conn.execute(
            """INSERT INTO users
               (id, username, email, role, password_hash, permissions, is_active, must_change_password, created_at, updated_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?)""",
            (new_id, req.username, req.email, ROLE_ADMIN,
             hash_password(req.password), json.dumps(perms), now, now, user["sub"]),
        )

        _log_audit(conn, user["sub"], user.get("username"), "create_admin",
                   target_type="user", target_id=new_id,
                   metadata={"new_username": req.username},
                   ip_address=request.client.host if request.client else None)

        # Notify the new admin
        _create_notification(conn, new_id,
            "Account Created",
            f"Your ScamShield admin account has been created by {user.get('username')}. Please change your password on first login.",
            "info")

        conn.commit()

    return {"message": f"Admin '{req.username}' created successfully.", "id": new_id}


@superadmin_router.get("/users/{user_id}")
def get_admin_user(user_id: str, user=Depends(require_superadmin)):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(404, "User not found.")
    d = dict(row)
    d.pop("password_hash", None)
    d["permissions"] = json.loads(d["permissions"]) if d["permissions"] else []
    return d


@superadmin_router.patch("/users/{user_id}")
def update_admin_user(user_id: str, req: UpdateAdminRequest, request: Request, user=Depends(require_superadmin)):
    if user_id == user["sub"]:
        # Can only change own email via this endpoint, not own active/suspend status
        if req.is_active is not None or req.is_suspended is not None:
            raise HTTPException(400, "Cannot modify your own active/suspend status here.")

    with get_db() as conn:
        target = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found.")

        # Non-superadmins cannot be elevated to superadmin via this endpoint
        updates = []
        params = []

        if req.email is not None:
            updates.append("email=?"); params.append(req.email)
        if req.permissions is not None:
            safe_perms = [p for p in req.permissions if p in ALL_PERMISSIONS]
            updates.append("permissions=?"); params.append(json.dumps(safe_perms))
        if req.is_active is not None:
            updates.append("is_active=?"); params.append(1 if req.is_active else 0)
        if req.is_suspended is not None:
            updates.append("is_suspended=?"); params.append(1 if req.is_suspended else 0)

        if not updates:
            raise HTTPException(400, "No fields to update.")

        updates.append("updated_at=?"); params.append(now_iso())
        params.append(user_id)

        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", params)

        _log_audit(conn, user["sub"], user.get("username"), "update_admin",
                   target_type="user", target_id=user_id,
                   metadata={"changes": req.model_dump(exclude_none=True)},
                   ip_address=request.client.host if request.client else None)
        conn.commit()

    return {"message": "User updated successfully."}


@superadmin_router.post("/users/{user_id}/reset-password")
def reset_admin_password(user_id: str, request: Request, user=Depends(require_superadmin)):
    """Generate a temporary password and force change on next login."""
    import secrets
    import string
    temp_pw = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))

    with get_db() as conn:
        target = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found.")

        conn.execute(
            "UPDATE users SET password_hash=?, must_change_password=1, updated_at=? WHERE id=?",
            (hash_password(temp_pw), now_iso(), user_id),
        )

        _log_audit(conn, user["sub"], user.get("username"), "reset_password",
                   target_type="user", target_id=user_id,
                   ip_address=request.client.host if request.client else None)

        _create_notification(conn, user_id,
            "Password Reset",
            f"Your password was reset by {user.get('username')}. A temporary password has been assigned. Please change it immediately after login.",
            "warning")

        conn.commit()

    return {
        "message": f"Password for '{target['username']}' reset. Share the temporary password securely.",
        "temp_password": temp_pw,  # Only shown once
    }


@superadmin_router.delete("/users/{user_id}")
def delete_admin_user(user_id: str, request: Request, user=Depends(require_superadmin)):
    if user_id == user["sub"]:
        raise HTTPException(400, "Cannot delete your own account.")

    with get_db() as conn:
        target = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found.")
        if target["role"] == "superadmin":
            raise HTTPException(403, "Cannot delete another super admin account.")

        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        _log_audit(conn, user["sub"], user.get("username"), "delete_admin",
                   target_type="user", target_id=user_id,
                   metadata={"deleted_username": target["username"]},
                   ip_address=request.client.host if request.client else None)
        conn.commit()

    return {"message": f"User '{target['username']}' deleted."}


@superadmin_router.get("/audit-log")
def get_audit_log(limit: int = 100, user=Depends(require_superadmin)):
    limit = min(limit, 500)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


@superadmin_router.get("/sessions")
def get_active_sessions(user=Depends(require_superadmin)):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT s.id, s.user_id, u.username, s.created_at, s.expires_at, s.ip_address, s.is_revoked
               FROM sessions s JOIN users u ON s.user_id=u.id
               WHERE s.is_revoked=0
               ORDER BY s.created_at DESC LIMIT 100"""
        ).fetchall()
    return [dict(r) for r in rows]


@superadmin_router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, user=Depends(require_superadmin)):
    with get_db() as conn:
        conn.execute("UPDATE sessions SET is_revoked=1 WHERE id=?", (session_id,))
        _log_audit(conn, user["sub"], user.get("username"), "revoke_session",
                   target_type="session", target_id=session_id)
        conn.commit()
    return {"message": "Session revoked."}


@superadmin_router.get("/settings")
def get_settings(user=Depends(require_superadmin)):
    with get_db() as conn:
        rows = conn.execute("SELECT key, value, updated_at FROM app_settings").fetchall()
    result = {}
    for r in rows:
        try:
            result[r["key"]] = json.loads(r["value"])
        except Exception:
            result[r["key"]] = r["value"]
    return result


@superadmin_router.patch("/settings/theme")
def update_theme(req: UpdateThemeRequest, user=Depends(require_superadmin)):
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No settings to update.")

    with get_db() as conn:
        for key, val in updates.items():
            conn.execute(
                "INSERT OR REPLACE INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                (key, str(val), now_iso(), user["sub"]),
            )
        _log_audit(conn, user["sub"], user.get("username"), "update_theme_settings",
                   metadata=updates)
        conn.commit()
    return {"message": "Theme settings updated.", "updated": updates}


@superadmin_router.get("/system-health")
def get_system_health(user=Depends(require_superadmin)):
    """Returns database status, detector models health, and integrations status."""
    import os
    from pathlib import Path

    # Database health
    db_status = "ok"
    db_size = 0
    table_counts = {}
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
            for tbl in ["users", "scan_history", "sessions", "audit_log", "notifications", "app_settings"]:
                count = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
                table_counts[tbl] = count
        db_path = Path(__file__).parent / "scamshield.db"
        if db_path.exists():
            db_size = db_path.stat().st_size
    except Exception as e:
        db_status = f"error: {str(e)}"

    # Optional libraries
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

    # Detection Models status
    models = {
        "url_analyzer": {
            "name": "Neon Sentinel URL Heuristics",
            "status": "operational",
            "version": "3.0.0",
            "capabilities": ["Punycode Spoofing", "Entropy Scoring", "TLD Reputation", "Deceptive Redirects"],
        },
        "message_analyzer": {
            "name": "Volt Runner Message Engine",
            "status": "operational",
            "version": "3.0.0",
            "capabilities": ["Bank Impersonation", "Urgency/Scarcity", "KYC Phishing", "Crypto Drainers", "Job/Task Scams"],
        },
        "email_analyzer": {
            "name": "Void Architect Email Forensics",
            "status": "operational",
            "version": "3.0.0",
            "capabilities": ["RFC 5322 Headers", "DKIM/SPF/DMARC", "Display Name Spoofing", "Multi-Hop Trace"],
        },
        "qr_analyzer": {
            "name": "Optical QR Security Decoder",
            "status": "operational" if pil_ok else "degraded",
            "version": "2.0.0",
            "capabilities": ["Image Normalization", "Code Extraction", "Payload Sanitization"],
            "pil_installed": pil_ok,
            "pyzbar_installed": pyzbar_ok,
        },
        "file_analyzer": {
            "name": "Static File Security Inspector",
            "status": "operational",
            "version": "2.0.0",
            "capabilities": ["Magic Byte Validation", "Double Extension Traps", "Polyglot Inspection"],
        },
    }

    # Integrations status
    integrations_status = {
        "virustotal": {"configured": bool(os.getenv("VIRUSTOTAL_API_KEY")), "service": "VirusTotal Threat API"},
        "safebrowsing": {"configured": bool(os.getenv("SAFEBROWSING_API_KEY")), "service": "Google Safe Browsing v4"},
        "abuseipdb": {"configured": bool(os.getenv("ABUSEIPDB_API_KEY")), "service": "AbuseIPDB Reputation API"},
        "threatfox": {"configured": True, "service": "ThreatFox IOC Feed (Built-in Heuristics)"},
    }

    return {
        "status": "operational" if db_status == "ok" else "degraded",
        "timestamp": now_iso(),
        "database": {
            "status": db_status,
            "size_bytes": db_size,
            "tables": table_counts,
            "journal_mode": "WAL",
        },
        "detection_models": models,
        "integrations": integrations_status,
    }


@superadmin_router.get("/integrations")
def get_integrations(user=Depends(require_superadmin)):
    """Returns stored integration settings with API keys safely masked."""
    with get_db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key='integrations'").fetchone()
    if not row:
        return {}
    try:
        data = json.loads(row[0])
    except Exception:
        data = {}

    # Mask keys for security
    masked = {}
    for key, conf in data.items():
        if isinstance(conf, dict):
            c = conf.copy()
            if "api_key" in c and c["api_key"]:
                k = c["api_key"]
                c["api_key"] = k[:4] + "****" + k[-4:] if len(k) > 8 else "****"
            masked[key] = c
        else:
            masked[key] = conf
    return masked


@superadmin_router.patch("/integrations")
def update_integrations(req: UpdateIntegrationsRequest, user=Depends(require_superadmin)):
    """Updates integration settings in database."""
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No integration settings provided.")

    with get_db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key='integrations'").fetchone()
        current = json.loads(row[0]) if row and row[0] else {}

        # Merge updates (preserve existing api_key if masked or unchanged)
        for key, new_conf in updates.items():
            if key not in current:
                current[key] = new_conf
            else:
                for k, v in new_conf.items():
                    if k == "api_key" and ("****" in str(v)):
                        continue  # Do not overwrite with masked placeholder
                    current[key][k] = v

        conn.execute(
            "INSERT OR REPLACE INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ("integrations", json.dumps(current), now_iso(), user["sub"]),
        )
        _log_audit(conn, user["sub"], user.get("username"), "update_integrations",
                   metadata={"updated_keys": list(updates.keys())})
        conn.commit()

    return {"message": "Integrations updated successfully.", "integrations": current}


@superadmin_router.get("/features")
def get_features(user=Depends(require_superadmin)):
    """Returns application feature settings."""
    with get_db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key='features'").fetchone()
    if not row:
        return {}
    try:
        return json.loads(row[0])
    except Exception:
        return {}


@superadmin_router.patch("/features")
def update_features(req: UpdateFeaturesRequest, user=Depends(require_superadmin)):
    """Updates application feature flags."""
    updates = req.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No feature settings provided.")

    with get_db() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key='features'").fetchone()
        current = json.loads(row[0]) if row and row[0] else {}
        current.update(updates)

        conn.execute(
            "INSERT OR REPLACE INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
            ("features", json.dumps(current), now_iso(), user["sub"]),
        )
        _log_audit(conn, user["sub"], user.get("username"), "update_features",
                   metadata=updates)
        conn.commit()

    return {"message": "Feature settings updated.", "features": current}


@superadmin_router.get("/errors")
def get_system_errors(limit: int = 50, user=Depends(require_superadmin)):
    """Returns recent failed operations and errors from audit log."""
    limit = min(limit, 200)
    with get_db() as conn:
        rows = conn.execute(
            """SELECT * FROM audit_log
               WHERE outcome != 'success' OR action LIKE '%error%' OR action LIKE '%fail%'
               ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]



# ── Public settings (for frontend to load theme) ─────────────────────────
public_settings_router = APIRouter(prefix="/settings", tags=["Settings"])


@public_settings_router.get("/theme")
def get_public_theme():
    """Returns current theme settings — public, no auth required."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT key, value FROM app_settings WHERE key IN ('active_theme','themes','neon_glow_intensity','bg_overlay_strength','animation_intensity')"
        ).fetchall()
    result = {}
    for r in rows:
        try:
            result[r["key"]] = json.loads(r["value"])
        except Exception:
            result[r["key"]] = r["value"]
    return result
