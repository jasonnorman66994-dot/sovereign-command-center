---
marp: true
theme: default
paginate: true
title: Mission Control SOC Brief
---

# Mission Control SOC Brief

Generated 2026-04-14

---

## Executive Posture

- Scenario coverage: 17
- Critical scenarios: 13
- Avg response latency: 3.56 minutes
- Avg containment latency: 4.38 minutes
- Highest signal density: SCENARIO_14_HYBRID_CLOUD_RANSOMWARE

---

## Terminal Incident

- Worst-day-of-the-year trigger: SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE
- Classification: Hardware Root-of-Trust Compromise - TPM/Secure Enclave Extraction
- Detection pressure: 6 primary signals
- Response load: 6 coordinated actions
- Operating mode: war-room coordination, continuity activation, forensic preservation, and full-scope compromise assessment

---

## Critical Scenario Priority

| Scenario | Risk | Signals | Actions |
|---|---|---:|---:|
| SCENARIO_14_HYBRID_CLOUD_RANSOMWARE | Critical | 7 | 6 |
| SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE | Critical | 6 | 6 |
| SCENARIO_16_OIDC_SIGNING_KEY_THEFT | Critical | 6 | 6 |
| SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE | Critical | 6 | 6 |
| SCENARIO_13_ZERO_DAY_EXPLOIT | Critical | 6 | 6 |
| SCENARIO_12_SUPPLY_CHAIN_POISONING | Critical | 6 | 6 |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | Critical | 6 | 6 |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | Critical | 6 | 6 |

---

## Chain Timeline

# Multi-Scenario Attack Chain Timeline

| Time  | Scenario | Key Event | User/Identity | Detection | Response |
|-------|----------|-----------|---------------|-----------|----------|
| 03:12 | 1        | Spam burst against monitored tenant | mail-relay-01 | Detected | Alert triggered, sender blocklist updated |
| 03:45 | 2        | Malware attachment detonated in inbox workflow | finance.user@example.com | Detected | Alert triggered, attachment quarantine initiated |
| 04:15 | 3        | Unauthorized access from stolen credentials | workstation-admin | Detected | Account disabled, session revoked |
| 06:02 | 4        | Business email compromise workflow abuse | ceo-mailbox@example.com | Detected | Mailbox rules disabled, alert triggered |
| 07:22 | 5        | OAuth abuse through rogue consent grant | app-registration-ops | Detected | OAuth grant deleted, consent review initiated |
| 10:12 | 6        | Vendor compromise creates downstream fraud path | vendor-automation-user | Detected | Vendor access disabled, rollback initiated |
| 13:22 | 7        | Insider misuse expands privileged access and staging | privileged.analyst@example.com | Detected | Privileged session disabled, exfil alert triggered |
| 15:03 | 8        | Token replay and impossible travel session hijack | dev_lead@example.com | Detected | Token blacklisted, account locked |
| 16:12 | 9        | Lateral movement via shadow OAuth application | dev_lead@example.com | Detected | OAuth grant deleted, malicious app disabled |
| 17:22 | 10       | Service principal hijack of production workload | sp-prod-backup-manager | Detected | Service Principal disabled, secrets rotated |
| 18:12 | 11       | K8s sidecar breakout reaches node boundary | sp-prod-backup-manager | Detected | Pod deleted, node cordoned, policy enforced |
| 19:12 | 12       | Supply-chain poisoning causes artifact drift | automation-bot (impersonated) | Detected | Pipeline halted, rollback initiated |
| 20:12 | 13       | Serialized exploit payload targets public profile API | profile-api | Behavioral anomaly | Endpoint disabled, alert triggered |
| 20:13 | 13       | Unexpected python process spawn and NET_ADMIN request | profile-api | Runtime anomaly | Pod isolated, secrets rotated |
| 20:14 | 13       | SSH lateral movement and 48 MB exfiltration to attacker IP | profile-api | UEBA escalation | Attacker IP blocked, secrets rotated |
| 20:15 | 13       | Cron persistence created after full runtime compromise | profile-api | UEBA critical | Forensics started, clean rebuild initiated |
| 21:12 | 14       | Untrusted encryptor launches on on-prem file server | fileserver-02 | EDR anomaly | Host isolated, ransomware response initiated |
| 21:12 | 14       | Golden ticket used by backup service account for hybrid pivot | svc-backup | Identity anomaly | Service account disabled, Kerberos review started |
| 21:13 | 14       | Cloud VM mass encryption and sustained CPU saturation detected | prod-app-01 | Compute anomaly | VM quarantined, backup jobs halted |
| 21:13 | 14       | Kubernetes workload deletes application data and overwrites root filesystem | payments-api | Runtime anomaly | Node quarantined, workload contained |
| 21:14 | 14       | Object storage rewritten to locked extensions at catastrophic volume | customer-records | Storage anomaly | Bucket access blocked, snapshot review initiated |
| 21:14 | 14       | Ransom note written to system banner on compromised host | hybrid-runtime | Behavioral anomaly | IR war room activated |
| 21:15 | 14       | Outbound status beacon confirms detonation success | hybrid-estate | C2 detection | Attacker IP blocked, executive escalation initiated |
| 22:12 | 15       | Federated token issued from compromised Tenant A using unknown device fingerprint | contractor_jane@tenantA.com | Federation anomaly | Federation trust review initiated, token issuance triaged |
| 22:12 | 15       | Federated identity assumes Tenant B global admin role outside normal policy | contractor_jane@tenantA.com | IAM anomaly | Cross-tenant role assumption blocked, privileged session revoked |
| 22:13 | 15       | Rogue service principal created and restricted secrets container accessed | shadow-app | Cloud control-plane anomaly | Service principal disabled, secret rotation initiated |
| 22:14 | 15       | Rogue federation trust created and 6.2 GB outbound transfer confirms exfiltration | tenantB federation plane | UEBA critical | Federation trust disabled, attacker IP blocked, emergency rotation started |
| 23:12 | 16       | IdP admin login from attacker IP bypasses MFA through abused trusted-device path | idp-admin | Identity anomaly | Admin session isolated, emergency IdP incident declared |
| 23:12 | 16       | OIDC signing key exported from keystore without approved change control | oidc-signing-key-01 | Keystore anomaly | Key rotation initiated, token trust review started |
| 23:13 | 16       | Forged 48-hour token validates and assumes GlobalAdmin without interactive MFA | ceo@example.com | Token policy anomaly | Global token invalidation initiated, privileged sessions revoked |
| 23:14 | 16       | Multi-service impersonation and rogue signing key creation establish persistence | idp trust plane | Identity collapse | Rogue key removed, IdP rebuild started |
| 23:15 | 16       | 12.4 GB outbound transfer confirms global identity-enabled exfiltration | global identity fabric | UEBA critical | Attacker IP blocked, leadership and compliance escalation activated |
| 00:12 | 17       | Non-allowlisted process reads TPM PCR state and opens enclave debug session on node-7 | node-7 | Hardware anomaly | Node isolated, hardware incident declared |
| 00:13 | 17       | Raw export of vm-disk-key confirms TPM or enclave key extraction | node-7 TPM | Trust-anchor anomaly | Key rotation and attestation revocation initiated |
| 00:13 | 17       | Healthy attestation report conflicts with boot log and PCR history | node-7 attestation | Attestation anomaly | Remote attestation trust revoked |
| 00:14 | 17       | Shadow VM clone created from prod-db-01 using stolen disk key and forged trust | shadow-db | Workload identity bypass | Clone quarantined, workload identity blocked |
| 00:15 | 17       | 9.4 GB outbound transfer confirms exfiltration from cloned trusted workload | shadow-db | UEBA critical | Attacker IP blocked, hardware rebuild workflow started |

---

## Incident Graph Backbone

- Graph nodes: 57
- Graph edges: 78
- Terminal graph path: SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE
- Ontology node types: 18
- Ontology relationship types: 19
- Use shared entities like users, OAuth apps, service principals, identity providers, nodes, workloads, and TPMs as correlation pivots.


---

## Campaign Modes and Package 8

- One scenario at a time: focused drill execution by scenario and control objective
- Multi-scenario chains: run correlated escalation paths (e.g., 3 -> 5 -> 9 -> 14)
- Full-spectrum campaign: Scenario 1 -> 20 in sequence (simulated, synthetic, safe)
- Package 8 deliverables: 8 documented artifacts
- Launcher profiles: 21 machine-runnable entries


---

## Latency Highlights

- SCENARIO_13_ZERO_DAY_EXPLOIT: containment latency 8.25 min
- SCENARIO_11_K8S_SIDECAR_BREAKOUT: containment latency 8.0 min
- SCENARIO_14_HYBRID_CLOUD_RANSOMWARE: containment latency 6.29 min
- SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE: containment latency 6.0 min
- SCENARIO_16_OIDC_SIGNING_KEY_THEFT: containment latency 6.0 min
- SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE: containment latency 6.0 min
- SCENARIO_3_UNAUTHORIZED_ACCESS: containment latency 5.0 min
- SCENARIO_6_VENDOR_COMPROMISE: containment latency 5.0 min
- SCENARIO_10_SERVICE_PRINCIPAL_HIJACK: containment latency 5.0 min
- SCENARIO_12_SUPPLY_CHAIN_POISONING: containment latency 5.0 min
- SCENARIO_1_SPAM_BURST: containment latency 2.0 min
- SCENARIO_2_MALWARE_ATTACHMENT: containment latency 2.0 min
- SCENARIO_4_BEC_ATTEMPT: containment latency 2.0 min
- SCENARIO_5_OAUTH_ABUSE: containment latency 2.0 min
- SCENARIO_7_INSIDER_MISUSE: containment latency 2.0 min
- SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL: containment latency 2.0 min
- SCENARIO_9_LATERAL_MOVEMENT_OAUTH: containment latency 2.0 min

---

## Recommended Board-Level Actions

- Treat hardware root-of-trust compromise - tpm/secure enclave extraction as the terminal planning case: pre-authorize cross-domain containment, executive escalation, and emergency credential rotation before detonation
- Freeze high-risk CI/CD and AI-assisted release paths on integrity drift
- Prioritize controls that reduce containment time in cloud and cluster scenarios
- Treat federation trust and machine identities as first-class breach surfaces
