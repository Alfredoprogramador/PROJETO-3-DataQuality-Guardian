"""
Camada 2 — Autorização
RBAC (Role-Based Access Control) + ABAC (Attribute-Based Access Control)
using Casbin with a policy model, with OPA integration for complex policies.
"""
from __future__ import annotations

import json
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import casbin
import httpx
from fastapi import Depends, HTTPException, status

from app.auth.jwt import get_current_user

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

class Role(str, Enum):
    ADMIN = "admin"
    DATA_STEWARD = "data_steward"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ---------------------------------------------------------------------------
# Casbin RBAC model (RFC ACL)
# ---------------------------------------------------------------------------

_MODEL_TEXT = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*")
"""

_POLICY_PATH = Path(__file__).parent / "rbac_policy.csv"


@lru_cache(maxsize=1)
def _get_enforcer() -> casbin.Enforcer:
    model = casbin.Model()
    model.load_model_from_text(_MODEL_TEXT)
    enforcer = casbin.Enforcer(model, str(_POLICY_PATH))
    return enforcer


def check_permission(subject: str, resource: str, action: str) -> bool:
    """Return True if subject has permission to perform action on resource."""
    enforcer = _get_enforcer()
    return enforcer.enforce(subject, resource, action)


def require_permission(resource: str, action: str):
    """FastAPI dependency factory — raises 403 if permission denied."""
    def _dep(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        subject = user.get("sub", "")
        role = user.get("role", Role.VIEWER)
        if not check_permission(role, resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {action} on {resource}",
            )
        return user
    return _dep


# ---------------------------------------------------------------------------
# ABAC — OPA policy evaluation
# ---------------------------------------------------------------------------

async def evaluate_opa_policy(
    policy_path: str,
    input_data: dict[str, Any],
) -> bool:
    """
    Call OPA's REST API to evaluate a policy.
    policy_path example: "dataquality/authz/allow"
    """
    from app.config import settings  # avoid circular import at module level

    url = f"{settings.OPA_URL}/v1/data/{policy_path}"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(url, json={"input": input_data})
        result = resp.json()
        return bool(result.get("result", False))
    except httpx.RequestError:
        # If OPA is unreachable, deny by default (fail-secure)
        return False


def require_opa_policy(policy_path: str, build_input: Any = None):
    """
    FastAPI async dependency factory for OPA-based ABAC.
    build_input: optional callable(user, request) -> dict
    """
    import asyncio
    from fastapi import Request

    def _dep_factory(
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        async def _check():
            inp = build_input(user, request) if build_input else {"user": user}
            allowed = await evaluate_opa_policy(policy_path, inp)
            if not allowed:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Policy denied")
            return user
        return asyncio.ensure_future(_check())

    return _dep_factory
