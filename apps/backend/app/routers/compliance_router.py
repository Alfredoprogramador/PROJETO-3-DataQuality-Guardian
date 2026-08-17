"""
Compliance router — LGPD/GDPR data subject rights and DPIA endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.jwt import get_current_user
from app.rbac.enforcer import require_permission

router = APIRouter()


class DSRCreateRequest(BaseModel):
    subject_id: str
    request_type: str   # access | rectification | erasure | portability | restriction
    notes: str = ""


class RetentionPolicyRequest(BaseModel):
    dataset: str
    retention_days: int
    classification: str = "SENSITIVE"
    legal_basis: str = ""


@router.post("/dsr")
async def create_data_subject_request(
    body: DSRCreateRequest,
    user=Depends(require_permission("governance_policies", "write")),
) -> dict:
    """Register a Data Subject Request (LGPD Art. 18 / GDPR Art. 15-20)."""
    # TODO: inject real DB session and call ComplianceService.create_dsr(...)
    return {
        "message": "DSR registered",
        "subject_id": body.subject_id,
        "request_type": body.request_type,
    }


@router.get("/dsr/overdue")
async def get_overdue_requests(
    user=Depends(require_permission("governance_policies", "read")),
) -> dict:
    """Return DSRs that have exceeded the 15-day legal deadline."""
    # TODO: inject real DB session and call ComplianceService.get_overdue_requests()
    return {"overdue": []}


@router.post("/retention-policy")
async def set_retention_policy(
    body: RetentionPolicyRequest,
    user=Depends(require_permission("governance_policies", "write")),
) -> dict:
    """Create or update a data retention policy for a dataset."""
    # TODO: inject real DB session and call ComplianceService.set_retention_policy(...)
    return {"message": "Retention policy saved", "dataset": body.dataset}


@router.get("/dpia/{dataset}")
async def generate_dpia(
    dataset: str,
    user=Depends(require_permission("governance_policies", "read")),
) -> dict:
    """Generate a Data Protection Impact Assessment (DPIA) report."""
    # TODO: inject real DB session and call ComplianceService.generate_dpia_report(...)
    return {
        "report_type": "DPIA",
        "dataset": dataset,
        "status": "stub — connect to ComplianceService for full report",
    }
