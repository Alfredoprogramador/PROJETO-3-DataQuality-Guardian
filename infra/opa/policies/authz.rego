# OPA policy — DataQuality Guardian ABAC
# Evaluates attribute-based access for PII-tagged resources.
package dataquality.authz

import rego.v1

# Default: deny
default allow := false

# Allow if user has the required role via RBAC
allow if {
    role := input.user.role
    resource := input.resource
    action := input.action
    role_permissions[role][_] == concat(".", [resource, action])
}

# Allow PII access only for compliance-approved users
allow if {
    input.resource_classification == "PII"
    input.user.compliance_approved == true
    input.user.role in {"admin", "data_steward"}
}

# Deny PII access outside business hours (UTC 08:00-20:00)
deny_outside_hours if {
    input.resource_classification == "PII"
    hour := time.clock(time.now_ns())[0]
    hour < 8
}

deny_outside_hours if {
    input.resource_classification == "PII"
    hour := time.clock(time.now_ns())[0]
    hour >= 20
}

allow if {
    not deny_outside_hours
    input.user.role in {"admin", "data_steward"}
    input.resource_classification == "PII"
    input.user.compliance_approved == true
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
