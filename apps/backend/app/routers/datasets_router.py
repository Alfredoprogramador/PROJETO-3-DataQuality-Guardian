"""
Datasets router — demonstrates RBAC-protected endpoints
with audit logging and PII masking.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from app.auth.jwt import get_current_user
from app.rbac.enforcer import require_permission
from app.security.middleware import limiter

router = APIRouter()


@router.get("/")
@limiter.limit("60/minute")
async def list_datasets(
    request: Request,
    user: dict[str, Any] = Depends(require_permission("datasets", "read")),
) -> dict[str, Any]:
    """List all datasets the authenticated user has read access to."""
    # TODO: implement real DB query via SQLAlchemy
    return {"datasets": [], "user": user.get("sub")}


@router.get("/{dataset_id}/preview")
@limiter.limit("30/minute")
async def preview_dataset(
    request: Request,
    dataset_id: str,
    user: dict[str, Any] = Depends(require_permission("datasets", "read")),
) -> dict[str, Any]:
    """
    Return a masked preview of dataset rows.
    PII is automatically detected and anonymized.
    """
    from app.pii.detector import mask_dataset_row

    # TODO: fetch real rows from the data source
    sample_rows = [
        {"name": "João Silva", "email": "joao.silva@example.com", "cpf": "123.456.789-00", "value": 1500.00},
        {"name": "Maria Souza", "email": "maria@example.com", "cpf": "987.654.321-00", "value": 2300.00},
    ]
    masked = [mask_dataset_row(row) for row in sample_rows]
    return {"dataset_id": dataset_id, "rows": masked, "pii_masked": True}
