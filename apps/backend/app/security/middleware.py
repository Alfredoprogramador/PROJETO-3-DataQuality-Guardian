"""
Camada 3 — Proteção da API
Security headers, CORS, rate limiting, secrets management.
"""
from __future__ import annotations

import os
from typing import Any

import secure
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.config import settings


# ---------------------------------------------------------------------------
# Rate limiter (shared instance — import this everywhere)
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])


def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please slow down."},
    )


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
_secure_headers = (
    secure.Secure()
    .hsts(max_age=63072000, include_subdomains=True, preload=True)
    .content_type_options()
    .frame_options()
    .xss_protection()
    .referrer_policy(policy="strict-origin-when-cross-origin")
    .cache_control(no_store=True)
    .csp(
        default_src="'self'",
        script_src="'self'",
        style_src="'self' 'unsafe-inline'",
        img_src="'self' data:",
        connect_src="'self'",
        frame_ancestors="'none'",
    )
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        _secure_headers.framework.fastapi(response)
        return response


# ---------------------------------------------------------------------------
# Secrets management — HashiCorp Vault client (with env-var fallback)
# ---------------------------------------------------------------------------

def get_secret(key: str, vault_path: str | None = None, vault_property: str | None = None) -> str:
    """
    Retrieve a secret from HashiCorp Vault if configured,
    otherwise fall back to environment variables.

    Args:
        key: Environment variable name used as fallback.
        vault_path: Vault KV path (e.g. "dqg/backend"). Defaults to key.
        vault_property: Property name within the Vault secret. Defaults to key.
    """
    path = vault_path or key
    prop = vault_property or key
    if settings.VAULT_ADDR and settings.VAULT_TOKEN:
        try:
            import hvac  # type: ignore

            client = hvac.Client(url=settings.VAULT_ADDR, token=settings.VAULT_TOKEN)
            if settings.VAULT_NAMESPACE:
                client.adapter.namespace = settings.VAULT_NAMESPACE
            read_response = client.secrets.kv.v2.read_secret_version(path=path)
            return read_response["data"]["data"][prop]
        except Exception:
            # Fall through to env-var fallback
            pass
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"Secret '{key}' not found in Vault (path={path}, property={prop}) or environment")
    return value


# ---------------------------------------------------------------------------
# Apply all middleware to the app
# ---------------------------------------------------------------------------

def apply_security_middleware(app: FastAPI) -> None:
    """Call this once during app startup."""
    # 1 — CORS (must be registered before other middleware)
    allowed_origins = [str(o) for o in settings.ALLOWED_ORIGINS] if settings.ALLOWED_ORIGINS else []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    # 2 — Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_middleware(SlowAPIMiddleware)

    # 3 — Security headers
    app.add_middleware(SecurityHeadersMiddleware)
