"""
Camada 1 — Autenticação & Identidade
Handles:
- JWT creation / verification (short-lived access + rotatable refresh tokens)
- Password hashing (bcrypt)
- TOTP-based MFA (RFC 6238)
- OIDC token introspection / verification (Keycloak / Auth0)
"""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pyotp
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def create_access_token(subject: str, extra_claims: dict[str, Any] | None = None) -> str:
    """Return a short-lived JWT access token."""
    expire = _utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": _utcnow(),
        "exp": expire,
        "type": "access",
        "jti": secrets.token_hex(16),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    """Return a rotatable refresh token."""
    expire = _utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    """Decode and validate a JWT.  Raises HTTPException on any failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise credentials_exception from exc
    if payload.get("type") != expected_type:
        raise credentials_exception
    return payload


# ---------------------------------------------------------------------------
# HTTP ******
# ---------------------------------------------------------------------------
_bearer = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict[str, Any]:
    """FastAPI dependency — returns decoded JWT claims."""
    return decode_token(credentials.credentials, expected_type="access")


# ---------------------------------------------------------------------------
# MFA — TOTP (RFC 6238)
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a new base32 TOTP secret for a user."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "DataQuality Guardian") -> str:
    """Return an otpauth:// URI (used to generate QR codes)."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code.  Allows ±1 window for clock drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# ---------------------------------------------------------------------------
# OIDC — verify token from Keycloak / Auth0 via introspection endpoint
# ---------------------------------------------------------------------------

async def verify_oidc_token(token: str) -> dict[str, Any]:
    """
    Verify an OIDC access token via the provider's introspection endpoint.
    Requires OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET to be set.
    """
    if not settings.OIDC_ISSUER_URL:
        raise HTTPException(status_code=501, detail="OIDC not configured")
    introspect_url = f"{settings.OIDC_ISSUER_URL}/protocol/openid-connect/token/introspect"
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            introspect_url,
            data={"token": token, "token_type_hint": "access_token"},
            auth=(settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET),
            timeout=10,
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OIDC introspection failed")
    claims = resp.json()
    if not claims.get("active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token not active")
    return claims
