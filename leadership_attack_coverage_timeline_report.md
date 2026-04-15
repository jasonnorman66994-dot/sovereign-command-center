# Leadership Report: Scenario 10-16 ATT&CK Coverage and Timeline

## Executive Summary

This report consolidates ATT&CK coverage and timeline progression across Scenario 10 through Scenario 16.

- Scenario coverage: 7 scenarios (10, 11, 12, 13, 14, 15, 16)
- ATT&CK tactics represented: 10
- ATT&CK techniques represented: 23
- Heat profile: 0 High, 4 Medium, 19 Low, 0 None
- Primary recurring cluster: Initial Access + Privilege Escalation + Defense Evasion + Exfiltration

## ATT&CK Heat Overview

Heat legend:

- High: technique appears in 5+ scenarios
- Medium: technique appears in 3-4 scenarios
- Low: technique appears in 1-2 scenarios
- None: not observed

| Category | Count |
|---|---:|
| High | 0 |
| Medium | 4 |
| Low | 19 |
| None | 0 |

### Most Recurrent Techniques (Medium)

| Technique | Technique ID | Scenario Frequency |
|---|---|---|
| Phishing / Spam Burst | T1566 | Scenario 10, 11, 13 |
| Abuse Elevation Control Mechanisms | T1548 | Scenario 10, 13, 16 |
| Indicator Removal | T1070 | Scenario 10, 11, 13 |
| Exfiltration Over Web Services | T1567 | Scenario 10, 13, 15 |

## Timeline Narrative Across Scenarios

### Scenario 10: Service Principal Hijack

- 17:22: suspicious foreign IP service principal login and stale secret usage
- 17:23: self-assigned privileged role attempt detected
- 17:24: cloud compute manipulation and extension execution observed
- 17:25: high-volume blob download indicates exfiltration activity
- 17:26: long-lived secret creation and UEBA score 9.9 confirm severe compromise

### Scenario 11: Kubernetes Sidecar Breakout

- 18:12: sidecar breakout and node compromise detected

### Scenario 12: Supply Chain Poisoning

- 19:12: CI/CD pipeline poisoning event detected

### Scenario 13: Zero-Day Exploit in Public API Service

- 20:12: serialized exploit payload delivered to API workload
- 20:13: runtime process spawn and capability abuse observed
- 20:14: lateral movement and exfiltration begin
- 20:15: persistence and UEBA escalation confirm full compromise

### Scenario 14: Hybrid Cloud Ransomware

- 21:12: ransomware detonation begins on on-prem system
- 21:13: identity pivot and cross-environment encryption spread confirmed
- 21:14: object storage locking and ransom-note deployment escalate impact
- 21:15: command-and-control beacon confirms detonation success

### Scenario 15: Cross-Tenant Federation Abuse

- 22:12: compromised tenant issues federation token to second tenant
- 22:12: federated identity granted high privilege outside policy
- 22:13: directory enumeration, service principal creation, and secret access indicate active takeover
- 22:14: rogue trust persistence and outbound transfer indicate cross-tenant exfiltration

### Scenario 16: Global Identity Provider Compromise

- 23:12: suspicious IdP admin login and MFA bypass detected
- 23:12: OIDC signing key exported without approved control
- 23:13: forged tokens used for privileged role assumption
- 23:14: SaaS impersonation expands and rogue key persistence created
- 23:15: large outbound transfer confirms mass theft after trust collapse

## Coverage Interpretation for Leadership

1. Current simulations consistently show adversary progression from initial entry to privilege elevation, evasion, and data loss.
2. Identity-plane compromise risk is prominent in later scenarios and can drive enterprise-wide blast radius.
3. Exfiltration is recurring across cloud, SaaS, and hybrid contexts, indicating high data protection exposure.

## Detection and Engineering Priorities

1. Privilege escalation and role-change monitoring, especially non-human identities.
2. Identity trust-anchor controls: key export detection, token anomaly detection, and global revocation readiness.
3. Defense-evasion hardening: log integrity protections and anti-tamper telemetry.
4. Exfiltration controls: outbound anomaly detection, high-volume transfer alerts, and policy-enforced egress restrictions.
5. Cross-tenant and federation governance: strict trust creation policies and approval workflows.

## Source Artifacts

- Unified ATT&CK dataset: data/unified_mitre_heatmap.json
- Unified ATT&CK report: unified_mitre_attack_heatmap.md
- Scenario files: scenario10_service_principal_hijack.md through scenario16_global_identity_provider_compromise.md
