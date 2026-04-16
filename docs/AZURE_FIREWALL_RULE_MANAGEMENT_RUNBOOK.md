# Azure Firewall Rule Management Runbook

Version: 1.0  
Last Updated: 2026-04-16  
Audience: Security Operations, Platform Engineering, Cloud Networking

---

## Purpose

This runbook standardizes Azure Firewall rule lifecycle management for enterprise hub-spoke and multi-region environments.

Goals:

- Reduce outage risk from rule changes
- Maintain least-privilege network posture
- Ensure traceability and rollback capability

---

## Rule Types and Usage

| Rule Type | Layer | Best For | Notes |
|---|---|---|---|
| Network Rule | L3/L4 | IP/port-based traffic control | Fastest evaluation path |
| Application Rule | L7 | FQDN and web egress allow lists | Use for internet egress governance |
| DNAT Rule | Inbound NAT | Controlled inbound service publishing | Prefer App Gateway/WAF where possible |

---

## Change Workflow

1. Intake request and classify as standard or emergency.
2. Validate business justification and source/destination scope.
3. Build candidate rule in non-production firewall policy.
4. Run connectivity and negative-path tests.
5. Approve through change board.
6. Deploy to production with maintenance window.
7. Monitor logs and metrics for 30-60 minutes.
8. Close change with evidence.

---

## Standard Change Procedure

### Step 1: Collect Inputs

Required fields:

- Request ID
- Environment (dev/test/prod)
- Source CIDR(s)
- Destination FQDN/IP
- Protocol and ports
- Expiration date (for temporary rules)
- Business owner and approver

### Step 2: Validate Existing Rules

```powershell
$fw = Get-AzFirewall -ResourceGroupName "rg-hub" -Name "scc-hub-fw"
$fw.NetworkRuleCollections | Select-Object Name, Priority
$fw.ApplicationRuleCollections | Select-Object Name, Priority
$fw.NatRuleCollections | Select-Object Name, Priority
```

### Step 3: Implement Rule in Staging Policy

```powershell
# Example: create or update network rule collection in staging policy
# Use explicit priorities and unique names to avoid shadowing.
$policy = Get-AzFirewallPolicy -ResourceGroupName "rg-hub-nonprod" -Name "scc-fw-policy-nonprod"
# Create/Update rule collection group via Az.Network cmdlets or IaC pipeline.
```

### Step 4: Validate with Log Analytics

```kusto
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where TimeGenerated > ago(30m)
| where msg_s has "Deny" or msg_s has "Allow"
| project TimeGenerated, action_s, src_ip_s, dst_ip_s, protocol_s, msg_s
| order by TimeGenerated desc
```

### Step 5: Promote via IaC

- Prefer Bicep/Terraform deployment to prevent drift.
- Tag rule collections with:
  - owner
  - requestId
  - expiryDate
  - classification

---

## Emergency Change Procedure

1. Incident commander approves emergency path.
2. Add minimal-scope temporary allow/deny rule.
3. Apply with highest safe priority.
4. Monitor impact for 15 minutes.
5. Open follow-up standard change for permanent fix.
6. Remove temporary rule within 24 hours.

---

## Rule Design Standards

- Default deny posture for outbound internet unless explicitly approved.
- Use FQDN tags and application rules where possible over broad IP ranges.
- Avoid any-any rules.
- Use narrow CIDR ranges and specific ports.
- Keep DNAT limited; terminate web ingress at Application Gateway/WAF when feasible.
- Define priority bands:
  - 100-199: platform critical
  - 200-399: business applications
  - 400-599: temporary exceptions

---

## Rollback Plan

- Keep previous firewall policy revision in source control.
- Roll back by redeploying last known good commit.
- Validate recovery with test matrix:
  - business critical flows restored
  - unauthorized paths still blocked

---

## Monitoring and KPIs

Track:

- Rule change failure rate
- Mean time to approve change
- Deny-to-allow ratio by application
- Temporary rule aging (>30 days)

Alerts:

- Sudden deny spikes for critical app destinations
- Any rule collection modified outside deployment pipeline

---

## Audit Checklist

- Rule has owner and ticket reference.
- Rule has expiration (if temporary).
- Rule scope is least privilege.
- Rule tested in non-production.
- Logs reviewed post-change.
- Rollback tested or documented.
