# OPA policy — DataQuality Guardian ABAC
# Evaluates attribute-based access for PII-tagged resources.
package dataquality.authz

import rego.v1

# Default: deny
default allow := false

# Allow if user has the required role via RBAC (non-PII resources only)
allow if {
    input.resource_classification != "PII"
    role := input.user.role
    resource := input.resource
    action := input.action
    role_permissions[role][_] == concat(".", [resource, action])
}

# Allow PII access only when ALL conditions are met:
#  1. User has compliance_approved attribute
#  2. User has an elevated role
#  3. Access is within business hours (UTC 08:00-20:00)
allow if {
    input.resource_classification == "PII"
    input.user.compliance_approved == true
    input.user.role in {"admin", "data_steward"}
    _within_business_hours
}

# Business hours guard (UTC 08:00-20:00)
_within_business_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 8
    hour < 20
}

# Role permission map (mirrors rbac_policy.csv)
role_permissions := {
    "admin": {"*.*"},
    "data_steward": {
        "datasets.read", "datasets.write",
        "quality_rules.read", "quality_rules.write",
        "governance_policies.read", "governance_policies.write",
        "catalog.read", "catalog.write",
        "lineage.read", "audit_logs.read",
    },
    "analyst": {
        "datasets.read",
        "quality_rules.read", "quality_rules.execute",
        "catalog.read", "lineage.read",
    },
    "viewer": {
        "datasets.read", "catalog.read", "lineage.read",
    },
}
