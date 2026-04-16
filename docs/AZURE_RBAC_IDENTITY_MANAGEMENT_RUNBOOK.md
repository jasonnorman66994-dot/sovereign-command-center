# Azure RBAC and Identity Management Runbook

Version: 1.0  
Last Updated: 2026-04-16  
Audience: IAM Administrators, Security Engineering, Platform Teams

---

## Purpose

Standardize identity onboarding, RBAC assignment, review, and emergency access for Azure workloads and operators.

---

## Principles

- Least privilege by default
- Prefer group-based role assignment over direct user assignment
- Use managed identities for workload access
- Time-bound elevated access
- Full audit trail for all privilege changes

---

## Role Assignment Workflow

1. Receive access request with justification.
2. Map requested action to minimum built-in role.
3. Assign role at smallest valid scope.
4. Define expiration/review date.
5. Capture ticket and approval evidence.

---

## Scope Decision Matrix

| Need | Scope |
|---|---|
| Single resource operations | Resource scope |
| App stack operations | Resource group scope |
| Platform operations | Subscription scope (exception-based) |

---

## Managed Identity Standards

- Use system-assigned identity for single-resource workloads.
- Use user-assigned identity for shared workload identity.
- Grant data-plane roles only where needed.
- Avoid broad Contributor assignments for workloads.

---

## Common Role Patterns

| Persona | Typical Roles |
|---|---|
| App Operator | Reader + specific service contributor at RG scope |
| Network Operator | Network Contributor at networking RG |
| Security Analyst | Security Reader + Log Analytics Reader |
| CI/CD Pipeline | Contributor at target RG + Key Vault Secrets User |

---

## Access Review Procedure

Cadence:

- Monthly for privileged groups
- Quarterly for all active role assignments

Review checks:

- Orphaned assignments
- Over-privileged principals
- Expired contractor access
- Inactive service principals

---

## Break-Glass Access

Use only for Sev1/Sev2 incidents when normal access paths fail.

Controls:

- Two designated emergency identities
- MFA and conditional access exclusions tightly scoped
- Session recording and immediate post-incident review
- Credential rotation after each use

---

## Audit Queries

Use Azure Activity Logs and Entra sign-in logs to verify:

- Role assignment create/delete events
- Privileged sign-in anomalies
- Service principal credential updates

Example KQL:

```kusto
AzureActivity
| where OperationNameValue has "Microsoft.Authorization/roleAssignments"
| where TimeGenerated > ago(30d)
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, ResourceGroup
| order by TimeGenerated desc
```

---

## Remediation Playbook

If excessive permissions detected:

1. Remove or downgrade assignment.
2. Validate workload continuity.
3. Replace with least-privilege role.
4. Document root cause and preventive control.

If compromised identity suspected:

1. Disable account or service principal.
2. Revoke sessions and rotate secrets/certs.
3. Review downstream access and blast radius.
4. Restore using clean identity and least-privilege roles.
