"""
DataQuality Guardian — FastAPI application entry point.
Security layers applied:
  1. JWT + OIDC authentication
  2. RBAC / ABAC via Casbin + OPA
  3. Rate limiting, security headers, CORS
  4. PII detection & AES-256-GCM field encryption
  5. Immutable HMAC-chained audit log
  8. LGPD/GDPR compliance module
"""
from fastapi import FastAPI

from app.security.middleware import apply_security_middleware
from app.routers import auth_router, compliance_router, datasets_router

app = FastAPI(
    title="DataQuality Guardian API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Apply all security middleware (CORS, rate limiting, security headers)
apply_security_middleware(app)

# Register routers
app.include_router(auth_router.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(datasets_router.router, prefix="/api/v1/datasets", tags=["datasets"])
app.include_router(compliance_router.router, prefix="/api/v1/compliance", tags=["compliance"])


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}
