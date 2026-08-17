"""
Camada 8 — Compliance LGPD/GDPR
Data subject rights: access, rectification, erasure.
Data retention policies. DPIA report generation.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Session

from app.audit.logger import AuditAction, AuditLogger


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Data Subject Request tracking
# ---------------------------------------------------------------------------

class DSRType(str, Enum):
    ACCESS = "access"           # Art. 15 GDPR / Art. 18 LGPD
    RECTIFICATION = "rectification"  # Art. 16 GDPR / Art. 18 LGPD
    ERASURE = "erasure"         # Art. 17 GDPR / Art. 18 LGPD (right to be forgotten)
    PORTABILITY = "portability" # Art. 20 GDPR / Art. 18 LGPD
    RESTRICTION = "restriction" # Art. 18 GDPR


class DSRStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"


class DataSubjectRequest(Base):
    __tablename__ = "data_subject_requests"

    id = Column(Integer, primary_key=True, index=True)
    subject_id = Column(String(256), nullable=False, index=True)    # user/data subject identifier
    request_type = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default=DSRStatus.PENDING)
    created_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True))
    notes = Column(Text)
    response_json = Column(Text)    # serialized response data


class DataRetentionPolicy(Base):
    __tablename__ = "data_retention_policies"

    id = Column(Integer, primary_key=True)
    dataset = Column(String(256), nullable=False, index=True)
    retention_days = Column(Integer, nullable=False)
    classification = Column(String(64))    # e.g. "PII", "SENSITIVE", "PUBLIC"
    legal_basis = Column(String(256))      # LGPD basis: consent, legitimate interest, etc.
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


# ---------------------------------------------------------------------------
# LGPD/GDPR service
# ---------------------------------------------------------------------------

class ComplianceService:
    """Handles data subject requests and retention policy enforcement."""

    RESPONSE_DEADLINE_DAYS = 15   # LGPD Art. 19: 15 business days

    def __init__(self, db: Session):
        self._db = db

    # --- Data Subject Requests ---

    def create_dsr(self, subject_id: str, request_type: DSRType, notes: str = "") -> DataSubjectRequest:
        req = DataSubjectRequest(
            subject_id=subject_id,
            request_type=request_type,
            status=DSRStatus.PENDING,
            created_at=datetime.now(tz=timezone.utc),
            notes=notes,
        )
        self._db.add(req)
        self._db.commit()
        self._db.refresh(req)
        return req

    def complete_dsr(self, dsr_id: int, response: dict[str, Any]) -> DataSubjectRequest:
        req = self._db.get(DataSubjectRequest, dsr_id)
        if not req:
            raise ValueError(f"DSR {dsr_id} not found")
        req.status = DSRStatus.COMPLETED
        req.completed_at = datetime.now(tz=timezone.utc)
        req.response_json = json.dumps(response)
        self._db.commit()
        self._db.refresh(req)
        return req

    def get_overdue_requests(self) -> list[DataSubjectRequest]:
        """Return all DSRs that have exceeded the legal deadline."""
        deadline = datetime.now(tz=timezone.utc) - timedelta(days=self.RESPONSE_DEADLINE_DAYS)
        return (
            self._db.query(DataSubjectRequest)
            .filter(
                DataSubjectRequest.status == DSRStatus.PENDING,
                DataSubjectRequest.created_at < deadline,
            )
            .all()
        )

    # --- Data Retention ---

    def set_retention_policy(
        self,
        dataset: str,
        retention_days: int,
        classification: str = "SENSITIVE",
        legal_basis: str = "",
    ) -> DataRetentionPolicy:
        now = datetime.now(tz=timezone.utc)
        existing = self._db.query(DataRetentionPolicy).filter_by(dataset=dataset).first()
        if existing:
            existing.retention_days = retention_days
            existing.classification = classification
            existing.legal_basis = legal_basis
            existing.updated_at = now
            self._db.commit()
            return existing

        policy = DataRetentionPolicy(
            dataset=dataset,
            retention_days=retention_days,
            classification=classification,
            legal_basis=legal_basis,
            created_at=now,
            updated_at=now,
        )
        self._db.add(policy)
        self._db.commit()
        self._db.refresh(policy)
        return policy

    def get_expired_data_sets(self) -> list[dict[str, Any]]:
        """Return datasets whose retention period has expired."""
        policies = self._db.query(DataRetentionPolicy).all()
        expired = []
        now = datetime.now(tz=timezone.utc)
        for p in policies:
            cutoff = now - timedelta(days=p.retention_days)
            expired.append({
                "dataset": p.dataset,
                "classification": p.classification,
                "retention_days": p.retention_days,
                "purge_before": cutoff.isoformat(),
            })
        return expired

    # --- DPIA Report ---

    def generate_dpia_report(self, dataset: str, contact_email: str = "") -> dict[str, Any]:
        """
        Generate a basic Data Protection Impact Assessment (DPIA) report
        (Art. 35 GDPR / Art. 38 LGPD).
        In production this should be enriched with real metadata from the catalog.
        """
        policy = self._db.query(DataRetentionPolicy).filter_by(dataset=dataset).first()
        return {
            "report_type": "DPIA",
            "dataset": dataset,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "data_classification": policy.classification if policy else "UNKNOWN",
            "retention_days": policy.retention_days if policy else None,
            "legal_basis": policy.legal_basis if policy else "",
            "contact_email": contact_email,
            "risks": [
                "Unauthorized access to sensitive data",
                "Data breach leading to exposure of personal data",
                "Excessive data retention beyond legal requirements",
            ],
            "mitigations": [
                "AES-256-GCM field-level encryption",
                "RBAC with least-privilege access",
                "Automated PII detection and masking",
                "Immutable audit logs with HMAC chaining",
                "Data retention policies enforced automatically",
            ],
            "lgpd_basis_art18": [
                "Confirmation of data processing",
                "Access to data",
                "Correction of incomplete/inaccurate data",
                "Anonymization, blocking or erasure of data",
                "Portability of data",
                "Deletion of data processed with consent",
            ],
        }
