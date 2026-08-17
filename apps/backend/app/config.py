"""
Application settings loaded from environment variables.
Secrets are never stored in code — they must come from Vault, AWS Secrets Manager
or environment variables injected at runtime (e.g. by External Secrets Operator).
"""
from __future__ import annotations

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # -------------------------------------------------------------------------
    # General
    # -------------------------------------------------------------------------
    APP_ENV: str = "development"
    DEBUG: bool = False

    # -------------------------------------------------------------------------
    # CORS — comma-separated list of allowed origins
    # -------------------------------------------------------------------------
    ALLOWED_ORIGINS: list[AnyHttpUrl] = Field(default_factory=list)

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def split_origins(cls, v: str | list) -> list:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # -------------------------------------------------------------------------
    # JWT
    # -------------------------------------------------------------------------
    JWT_SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15        # short-lived
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # -------------------------------------------------------------------------
    # OIDC / Keycloak
    # -------------------------------------------------------------------------
    OIDC_ISSUER_URL: str = ""          # e.g. https://keycloak.example.com/realms/dqg
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str = Field(...)

    # -------------------------------------------------------------------------
    # Audit log HMAC signing key  (min 32 bytes)
    # -------------------------------------------------------------------------
    AUDIT_HMAC_KEY: str = Field(..., min_length=32)

    # -------------------------------------------------------------------------
    # Encryption key for sensitive columns (AES-256 — must be 32 bytes hex)
    # -------------------------------------------------------------------------
    FIELD_ENCRYPTION_KEY_HEX: str = Field(..., min_length=64, max_length=64)

    # -------------------------------------------------------------------------
    # OPA / Policy engine
    # -------------------------------------------------------------------------
    OPA_URL: str = "http://opa:8181"

    # -------------------------------------------------------------------------
    # HashiCorp Vault (optional — falls back to env vars)
    # -------------------------------------------------------------------------
    VAULT_ADDR: str = ""
    VAULT_TOKEN: str = ""
    VAULT_NAMESPACE: str = ""

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_DEFAULT: str = "100/minute"


settings = Settings()  # type: ignore[call-arg]
