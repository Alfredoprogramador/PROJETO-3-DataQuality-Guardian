"""Auth router — login, refresh, MFA enrollment."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator

from app.auth.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    verify_password,
    verify_totp,
)
from app.security.middleware import limiter
from fastapi import Request

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response schemas (Pydantic v2)
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: EmailStr
    password: str
    totp_code: str | None = None

    @field_validator("password")
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("password must not be empty")
        return v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


class MFAEnrollResponse(BaseModel):
    totp_secret: str
    totp_uri: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest) -> TokenResponse:
    """
    Authenticate with username + password (+ optional TOTP).
    In production, look up the user in the database and verify the stored hash.
    """
    # TODO: replace with real user lookup from DB
    # Stub: accept any non-empty credential for scaffolding
    if not body.username or not body.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # MFA verification (if the user has TOTP enabled)
    # In production: fetch stored totp_secret from DB for this user
    # if user.totp_enabled and not verify_totp(user.totp_secret, body.totp_code or ""):
    #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    from app.config import settings

    claims = {"email": body.username, "role": "viewer"}
    access_token = create_access_token(subject=body.username, extra_claims=claims)
    refresh_token = create_refresh_token(subject=body.username)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
async def refresh(request: Request, body: RefreshRequest) -> TokenResponse:
    """Rotate a refresh token and issue a new access + refresh token pair."""
    payload = decode_token(body.refresh_token, expected_type="refresh")
    subject: str = payload["sub"]

    from app.config import settings

    access_token = create_access_token(subject=subject)
    new_refresh_token = create_refresh_token(subject=subject)  # rotate

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/mfa/enroll", response_model=MFAEnrollResponse)
async def enroll_mfa(username: str) -> MFAEnrollResponse:
    """
    Generate a new TOTP secret for a user.
    The client should display the QR code from `totp_uri` and verify a code
    before activating MFA on the account.
    """
    secret = generate_totp_secret()
    uri = get_totp_uri(secret=secret, username=username)
    # TODO: persist secret (encrypted) in DB and mark as pending activation
    return MFAEnrollResponse(totp_secret=secret, totp_uri=uri)


@router.post("/mfa/verify")
async def verify_mfa(username: str, code: str, secret: str) -> dict[str, bool]:
    """Verify a TOTP code during MFA enrollment confirmation."""
    valid = verify_totp(secret=secret, code=code)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")
    # TODO: activate MFA in DB for this user
    return {"verified": True}
