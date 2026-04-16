# Azure Multi-Region Failover and DR Playbook

Version: 1.0  
Last Updated: 2026-04-16  
Audience: SRE, Platform Engineering, Incident Management

---

## Objective

Provide deterministic failover and recovery procedures for primary-secondary Azure regions supporting mission-critical workloads.

---

## Assumptions

- Active-passive or active-active regional pattern exists.
- Global routing via Traffic Manager or Front Door is configured.
- Data layer replication is in place (SQL failover group, Cosmos DB multi-region, or equivalent).
- Runbook tested in non-production in the last 90 days.

---

## Severity Model

| Severity | Condition | Action |
|---|---|---|
| Sev1 | Full regional outage | Immediate regional failover |
| Sev2 | Partial service degradation | Weighted traffic shift |
| Sev3 | Isolated component outage | Component-level remediation |

---

## Regional Failover Procedure

### Step 1: Incident Declaration

- Confirm outage impact and blast radius.
- Appoint incident commander and communication lead.

### Step 2: Data Plane Readiness

- Confirm replica health and acceptable RPO.
- For SQL failover groups, verify secondary is synchronized.
- For storage, verify replication status and accessibility.

### Step 3: Traffic Shift

- Set primary endpoint disabled or lower weight.
- Promote secondary endpoint priority.

Example sequence:

1. Update global routing profile.
2. Wait for health probe convergence.
3. Validate client traffic now terminates in secondary region.

### Step 4: Validate Service Integrity

- Execute smoke tests:
  - authentication
  - CRUD flows
  - background jobs
  - external integrations

### Step 5: Stabilize

- Monitor error rates, saturation, and dependency health for at least 60 minutes.

---

## Controlled Failback Procedure

1. Restore primary region platform health.
2. Resynchronize data and verify no replication lag risk.
3. Shift a small traffic percentage to primary.
4. Validate telemetry and business transactions.
5. Complete full failback when stable.

---

## RTO and RPO Validation

| Service Tier | Target RTO | Target RPO |
|---|---|---|
| Tier 0 critical | <= 15 min | <= 5 min |
| Tier 1 business | <= 30 min | <= 15 min |
| Tier 2 support | <= 4 hr | <= 1 hr |

Track actuals during drills and incidents.

---

## Operational Controls

- Enforce deployment parity across regions.
- Use immutable IaC artifacts for both regions.
- Maintain runbook-linked dashboards and alerts.
- Require quarterly DR exercises.

---

## Drill Cadence

- Monthly tabletop review
- Quarterly technical failover drill
- Annual full business continuity exercise

---

## Evidence to Capture

- Incident timeline
- Routing profile changes
- Data failover timestamps
- Validation test outcomes
- Stakeholder communications
- Follow-up corrective actions
