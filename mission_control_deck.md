---
marp: true
theme: default
paginate: true
headingDivider: 2
---

# Mission Control Deck

Generated 2026-04-14

## Program KPIs
- Scenario coverage: 11
- Critical scenarios: 10
- Avg dwell time: 4.83 minutes
- Avg response latency: 5.17 minutes
- Avg containment latency: 10.0 minutes

## Severity Overview
| Scenario | Risk | Signals | Actions |
|---|---|---:|---:|
| SCENARIO_12_SUPPLY_CHAIN_POISONING | Critical | 6 | 6 |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | Critical | 6 | 6 |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | Critical | 6 | 6 |
| SCENARIO_9_LATERAL_MOVEMENT_OAUTH | Critical | 5 | 6 |
| SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL | Critical | 5 | 6 |
| SCENARIO_7_INSIDER_MISUSE | Critical | 5 | 6 |
| SCENARIO_6_VENDOR_COMPROMISE | Critical | 5 | 6 |
| SCENARIO_13_FEDERATION_TRUST_ABUSE | Critical | 5 | 6 |
| SCENARIO_13_AI_PROMPT_INJECTION | Critical | 5 | 6 |
| SCENARIO8_INSIDER_EXFILTRATION | Critical | 5 | 3 |
| SCENARIO_5_OAUTH_ABUSE | High | 4 | 6 |

## SCENARIO_12_SUPPLY_CHAIN_POISONING
- Risk: Critical
- Top signals: Artifact hash mismatch, Malicious build step, Outbound callback to attacker
- Top actions: Audit pipeline history, Block attacker IP, Halt deployments

## SCENARIO_11_K8S_SIDECAR_BREAKOUT
- Risk: Critical
- Top signals: Cloud API secret access, Host filesystem mount attempt, Kubelet client cert access
- Top actions: Audit cloud API calls, Isolate and drain node, Quarantine compromised pod

## SCENARIO_10_SERVICE_PRINCIPAL_HIJACK
- Risk: Critical
- Top signals: Foreign IP service principal login, Large blob downloads, Long-lived secret creation
- Top actions: Audit IAM role changes, Block attacker IP, Disable service principal

## SCENARIO_9_LATERAL_MOVEMENT_OAUTH
- Risk: Critical
- Top signals: App impersonating multiple users, Large repo and mailbox exports, Long-lived refresh token
- Top actions: Audit app permission history, Block attacker IP, Disable OAuth app

## SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL
- Risk: Critical
- Top signals: Device fingerprint mismatch, Impossible travel, Same token used from two locations
- Top actions: Block suspicious IP, Force MFA re-enrollment, Invalidate token

## SCENARIO_7_INSIDER_MISUSE
- Risk: Critical
- Top signals: Access to sensitive finance files, High UEBA anomaly score, Large upload to personal cloud
- Top actions: Analyze ZIP contents, Block outbound uploads, Disable user account
