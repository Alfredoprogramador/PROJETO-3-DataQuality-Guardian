"""
Camada 5 — Auditoria & Observabilidade de Segurança
Immutable audit log with HMAC-SHA256 chaining.
Each log entry is signed with HMAC(key, prev_hash + payload).
This makes tampering detectable: any modification breaks the chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


# ---------------------------------------------------------------------------
# Database model
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    actor = Column(String(256), nullable=False, index=True)        # user sub / service account
    action = Column(String(128), nullable=False, index=True)       # e.g. "datasets.read"
    resource = Column(String(256), nullable=False)                 # e.g. "datasets/customer_orders"
    outcome = Column(String(16), nullable=False)                   # "allow" | "deny" | "error"
    ip_address = Column(String(64))
    user_agent = Column(String(512))
    metadata_json = Column(Text)                                   # arbitrary extra context
    payload_hash = Column(String(64), nullable=False)              # SHA-256 of payload
    chain_hmac = Column(String(64), nullable=False)                # HMAC chaining signature
    prev_chain_hmac = Column(String(64), nullable=False)           # previous entry's chain_hmac


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

def _hmac_sign(key: bytes, data: str) -> str:
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


class AuditAction(str, Enum):
    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token_refresh"
    MFA_CHALLENGE = "auth.mfa_challenge"
    DATASET_READ = "datasets.read"
    DATASET_WRITE = "datasets.write"
    QUALITY_RUN = "quality.run"
    POLICY_CHANGE = "governance.policy_change"
    CATALOG_READ = "catalog.read"
    CATALOG_WRITE = "catalog.write"
    PII_SCAN = "pii.scan"
    SECRET_ACCESS = "secrets.access"
    ADMIN_ACTION = "admin.action"


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Write immutable, HMAC-chained audit log entries.
    Typical usage:
        logger = AuditLogger(db_session)
        await logger.log(actor="user@example.com", action=AuditAction.DATASET_READ, ...)
    """

    GENESIS_HMAC = "0" * 64   # sentinel for the first entry in the chain

    def __init__(self, db_session):
        self._db = db_session
        self._key = settings.AUDIT_HMAC_KEY.encode()

    def _get_prev_hmac(self) -> str:
        """Fetch the latest chain_hmac from the DB (or genesis sentinel)."""
        result = (
            self._db.query(AuditLog.chain_hmac)
            .order_by(AuditLog.id.desc())
            .first()
        )
        return result[0] if result else self.GENESIS_HMAC

    def log(
        self,
        actor: str,
        action: str,
        resource: str,
        outcome: str = "allow",
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditLog:
        """
        Create and persist a new audit log entry.
        Returns the persisted AuditLog instance.
        """
        now = datetime.now(tz=timezone.utc)
        metadata_json = json.dumps(metadata or {})
        payload = json.dumps({
            "ts": now.isoformat(),
            "actor": actor,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "ip": ip_address,
            "meta": metadata_json,
        }, sort_keys=True)

        payload_hash = _sha256(payload)
        prev_hmac = self._get_prev_hmac()
        chain_hmac = _hmac_sign(self._key, prev_hmac + payload_hash)

        entry = AuditLog(
            timestamp=now,
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_json=metadata_json,
            payload_hash=payload_hash,
            chain_hmac=chain_hmac,
            prev_chain_hmac=prev_hmac,
        )
        self._db.add(entry)
        self._db.commit()
        self._db.refresh(entry)
        return entry

    def verify_chain(self, entries: list[AuditLog]) -> bool:
        """
        Verify the integrity of a sequence of audit log entries.
        Returns True if the chain is intact, False if any tampering is detected.
        """
        if not entries:
            return True
        prev_hmac = self.GENESIS_HMAC if entries[0].prev_chain_hmac == self.GENESIS_HMAC else entries[0].prev_chain_hmac
        for entry in entries:
            if entry.prev_chain_hmac != prev_hmac:
                return False
            expected = _hmac_sign(self._key, entry.prev_chain_hmac + entry.payload_hash)
            if not hmac.compare_digest(expected, entry.chain_hmac):
                return False
            prev_hmac = entry.chain_hmac
        return True
