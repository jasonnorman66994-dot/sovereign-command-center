# Mission Control Unified Report — 2026-04-14

This report combines executive narrative, prioritized drill-down, chain timeline, and KPI metrics.

## Severity Scorecard

| Scenario | Severity | Scorebar | Signals | Containment Latency |
|---|---|---|---:|---:|
| SCENARIO_13_ZERO_DAY_EXPLOIT | Critical | [####] | 6 | 8.25 |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | Critical | [####] | 6 | 8.0 |
| SCENARIO_14_HYBRID_CLOUD_RANSOMWARE | Critical | [####] | 7 | 6.29 |
| SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE | Critical | [####] | 6 | 6.0 |
| SCENARIO_16_OIDC_SIGNING_KEY_THEFT | Critical | [####] | 6 | 6.0 |
| SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE | Critical | [####] | 6 | 6.0 |
| SCENARIO_12_SUPPLY_CHAIN_POISONING | Critical | [####] | 6 | 5.0 |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | Critical | [####] | 6 | 5.0 |
| SCENARIO_6_VENDOR_COMPROMISE | Critical | [####] | 5 | 5.0 |
| SCENARIO_9_LATERAL_MOVEMENT_OAUTH | Critical | [####] | 5 | 2.0 |
| SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL | Critical | [####] | 5 | 2.0 |
| SCENARIO_7_INSIDER_MISUSE | Critical | [####] | 5 | 2.0 |
| SCENARIO_4_BEC_ATTEMPT | Critical | [####] | 5 | 2.0 |
| SCENARIO_3_UNAUTHORIZED_ACCESS | High | [### ] | 4 | 5.0 |
| SCENARIO_5_OAUTH_ABUSE | High | [### ] | 4 | 2.0 |
| SCENARIO_2_MALWARE_ATTACHMENT | High | [### ] | 4 | 2.0 |
| SCENARIO_1_SPAM_BURST | Medium | [##  ] | 4 | 2.0 |

## Executive Summary

# SOC Executive Summary — 2026-04-14
## Terminal Incident
SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE is the worst-day-of-the-year event in this SOC training universe: a hardware root-of-trust compromise - tpm/secure enclave extraction requiring immediate containment, executive escalation, forensic preservation, and continuity actions across the full environment.

- Risk posture: Critical
- Detection pressure: 6 primary signals
- Required response tracks: 6 coordinated action(s)

## Scenario Overview
| Scenario | Incidents | Max Severity | Classification |
|----------|-----------|--------------|----------------|
| SCENARIO_1_SPAM_BURST | 4 | Medium | Spam burst / relay probing |
| SCENARIO_2_MALWARE_ATTACHMENT | 4 | High | Malware attachment attempt |
| SCENARIO_3_UNAUTHORIZED_ACCESS | 4 | High | Unauthorized access / credential compromise |
| SCENARIO_4_BEC_ATTEMPT | 5 | Critical | Business Email Compromise (BEC) - Active Account Takeover |
| SCENARIO_5_OAUTH_ABUSE | 4 | High | OAuth Consent Abuse |
| SCENARIO_6_VENDOR_COMPROMISE | 5 | Critical | Vendor Email Compromise |
| SCENARIO_7_INSIDER_MISUSE | 5 | Critical | Insider Misuse - Privilege Creep and Data Exfiltration |
| SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL | 5 | Critical | Token Replay and Impossible Travel |
| SCENARIO_9_LATERAL_MOVEMENT_OAUTH | 5 | Critical | Lateral Movement via Compromised OAuth App |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | 6 | Critical | Cloud Workload Compromise - Service Principal Hijack |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | 6 | Critical | Kubernetes Container Breakout and Node Compromise |
| SCENARIO_12_SUPPLY_CHAIN_POISONING | 6 | Critical | Supply-Chain Compromise - CI/CD Pipeline Poisoning |
| SCENARIO_13_ZERO_DAY_EXPLOIT | 6 | Critical | Zero-Day Exploitation and Runtime Compromise |
| SCENARIO_14_HYBRID_CLOUD_RANSOMWARE | 7 | Critical | Hybrid-Cloud Ransomware Detonation |
| SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE | 6 | Critical | Cross-Tenant Cloud Takeover - Federation Abuse |
| SCENARIO_16_OIDC_SIGNING_KEY_THEFT | 6 | Critical | Global Identity Provider Compromise - OIDC Signing Key Theft |
| SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE | 6 | Critical | Hardware Root-of-Trust Compromise - TPM/Secure Enclave Extraction |

## Key Signals and Actions by Scenario
### SCENARIO_1_SPAM_BURST
**Signals:** Authentication failures, Bot-like reconnect behavior, High-frequency inbound attempts, Relay access denied
**Actions:** Block source IP, Increase rate-limit thresholds, Monitor for repeat attempts, Verify no internal accounts were compromised

### SCENARIO_2_MALWARE_ATTACHMENT
**Signals:** Known test signature, Malware signature match, Quarantine event, Suspicious sender identity
**Actions:** Check whether similar messages bypassed filters, Confirm quarantine, Notify security team, Validate AV signatures are up to date

### SCENARIO_3_UNAUTHORIZED_ACCESS
**Signals:** Credential stuffing pattern, Multiple failed logins from rotating IPs, Sudden login success, Suspicious session start
**Actions:** Block suspicious IPs, Disable account, Enforce MFA, Force password reset, Investigate credential theft vector, Terminate active session

### SCENARIO_4_BEC_ATTEMPT
**Signals:** Financial urgency keywords, New device fingerprint, Reply-to changed to external domain, Successful login from unusual IP, Suspicious mailbox rules
**Actions:** Block suspicious IP, Disable executive account, Inspect mailbox rules, Notify finance team, Review sent items for fraud, Revoke OAuth tokens, Terminate active sessions

### SCENARIO_5_OAUTH_ABUSE
**Signals:** Foreign IP token use, High-risk scopes, Mailbox forwarding rule, Unverified OAuth app
**Actions:** Delete mailbox rules, Notify leadership, Remove malicious app, Reset credentials, Revoke OAuth tokens, Tenant-wide app audit

### SCENARIO_6_VENDOR_COMPROMISE
**Signals:** AP team engagement, Changed banking details, Unusual vendor login region, Urgency language, Vendor mailbox forwarding rule
**Actions:** Block vendor temporarily, Contact vendor security, Notify finance leadership, Quarantine email, Review AP replies, Stop payment

### SCENARIO_7_INSIDER_MISUSE
**Signals:** Access to sensitive finance files, High UEBA anomaly score, Large upload to personal cloud, Unauthorized role change, ZIP file creation
**Actions:** Analyze ZIP contents, Block outbound uploads, Disable user account, Notify HR and security leadership, Revert unauthorized privileges, Review role change logs

### SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL
**Signals:** Device fingerprint mismatch, Impossible travel, Same token used from two locations, Sensitive repo access, Token replay warning
**Actions:** Block suspicious IP, Force MFA re-enrollment, Invalidate token, Review repo downloads, Revoke all sessions, Rotate accessed secrets

### SCENARIO_9_LATERAL_MOVEMENT_OAUTH
**Signals:** App impersonating multiple users, Large repo and mailbox exports, Long-lived refresh token, Single attacker IP, Unauthorized permission escalation
**Actions:** Audit app permission history, Block attacker IP, Disable OAuth app, Investigate initial compromise, Revoke app tokens, Rotate accessed secrets

### SCENARIO_10_SERVICE_PRINCIPAL_HIJACK
**Signals:** Foreign IP service principal login, Large blob downloads, Long-lived secret creation, Old leaked secret, Unauthorized role assignment attempt, VM manipulation
**Actions:** Audit IAM role changes, Block attacker IP, Disable service principal, Revoke secrets and tokens, Rotate all workload secrets, Stop malicious VM

### SCENARIO_11_K8S_SIDECAR_BREAKOUT
**Signals:** Cloud API secret access, Host filesystem mount attempt, Kubelet client cert access, SYS_ADMIN capability escalation, Sidecar integrity violation, Unauthorized exec into container
**Actions:** Audit cloud API calls, Isolate and drain node, Quarantine compromised pod, Rebuild node from clean image, Revoke node IAM credentials, Rotate kubelet certificates

### SCENARIO_12_SUPPLY_CHAIN_POISONING
**Signals:** Artifact hash mismatch, Malicious build step, Outbound callback to attacker, Secret harvesting behavior, Unauthorized commit to pipeline template, Unknown GPG signature
**Actions:** Audit pipeline history, Block attacker IP, Halt deployments, Rebuild CI/CD environment, Revoke automation-bot credentials, Roll back artifacts

### SCENARIO_13_ZERO_DAY_EXPLOIT
**Signals:** Large outbound data transfer, Privilege escalation attempt, SSH lateral movement, Unauthorized cron job, Unexpected process spawn, Unexpected serialized payload
**Actions:** Block attacker IP, Capture forensic artifacts, Disable vulnerable endpoint, Isolate compromised pod, Patch vulnerable service, Rotate secrets

### SCENARIO_14_HYBRID_CLOUD_RANSOMWARE
**Signals:** Golden ticket activity, Kubernetes data destruction, Mass file encryption, Object storage rewrite, Outbound C2 beacon, Ransom note deployment, Untrusted binary execution
**Actions:** Block attacker IP, Capture forensic artifacts, Disable compromised accounts, Isolate affected systems, Restore from offline backups, Rotate credentials

### SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE
**Signals:** Creation of rogue service principal, Cross-tenant secret access, Federated identity assuming privileged role, Large outbound exfiltration, Suspicious federation token issuance, Unauthorized federation trust creation
**Actions:** Audit role assumptions, Block attacker IP, Disable compromised identities, Disable federation trust, Rebuild federation trust securely, Revoke federation tokens

### SCENARIO_16_OIDC_SIGNING_KEY_THEFT
**Signals:** Forged tokens with abnormal lifetimes, Large outbound exfiltration, Privilege escalation via forged tokens, Rogue signing key creation, Suspicious IdP admin login, Unauthorized signing key export
**Actions:** Audit token issuance, Block attacker IP, Disable IdP admin accounts, Invalidate all tokens, Rebuild IdP from clean state, Rotate OIDC signing keys

### SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE
**Signals:** Enclave debug session, Forged attestation, Large outbound exfiltration, Raw key export, Unauthorized TPM access, VM clone using stolen key
**Actions:** Audit VM clone operations, Block attacker IP, Isolate compromised node, Rebuild node from clean hardware, Revoke attestation trust, Rotate TPM/enclave keys

---
*Generated automatically by SOC analytics pipeline.*

## Drill-Down Report

# SOC Drill-Down Report — 2026-04-14

## Scenario Prioritization

| Scenario | Risk | Signals | Actions | Classification |
|---|---|---:|---:|---|
| SCENARIO_14_HYBRID_CLOUD_RANSOMWARE | Critical | 7 | 6 | Hybrid-Cloud Ransomware Detonation |
| SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE | Critical | 6 | 6 | Hardware Root-of-Trust Compromise - TPM/Secure Enclave Extraction |
| SCENARIO_16_OIDC_SIGNING_KEY_THEFT | Critical | 6 | 6 | Global Identity Provider Compromise - OIDC Signing Key Theft |
| SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE | Critical | 6 | 6 | Cross-Tenant Cloud Takeover - Federation Abuse |
| SCENARIO_13_ZERO_DAY_EXPLOIT | Critical | 6 | 6 | Zero-Day Exploitation and Runtime Compromise |
| SCENARIO_12_SUPPLY_CHAIN_POISONING | Critical | 6 | 6 | Supply-Chain Compromise - CI/CD Pipeline Poisoning |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | Critical | 6 | 6 | Kubernetes Container Breakout and Node Compromise |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | Critical | 6 | 6 | Cloud Workload Compromise - Service Principal Hijack |
| SCENARIO_4_BEC_ATTEMPT | Critical | 5 | 7 | Business Email Compromise (BEC) - Active Account Takeover |
| SCENARIO_9_LATERAL_MOVEMENT_OAUTH | Critical | 5 | 6 | Lateral Movement via Compromised OAuth App |
| SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL | Critical | 5 | 6 | Token Replay and Impossible Travel |
| SCENARIO_7_INSIDER_MISUSE | Critical | 5 | 6 | Insider Misuse - Privilege Creep and Data Exfiltration |
| SCENARIO_6_VENDOR_COMPROMISE | Critical | 5 | 6 | Vendor Email Compromise |
| SCENARIO_5_OAUTH_ABUSE | High | 4 | 6 | OAuth Consent Abuse |
| SCENARIO_3_UNAUTHORIZED_ACCESS | High | 4 | 6 | Unauthorized access / credential compromise |
| SCENARIO_2_MALWARE_ATTACHMENT | High | 4 | 4 | Malware attachment attempt |
| SCENARIO_1_SPAM_BURST | Medium | 4 | 4 | Spam burst / relay probing |

## Drill-Down Highlights

### SCENARIO_14_HYBRID_CLOUD_RANSOMWARE
- Top signals: Golden ticket activity; Kubernetes data destruction; Mass file encryption
- Top actions: Block attacker IP; Capture forensic artifacts; Disable compromised accounts
### SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE
- Top signals: Enclave debug session; Forged attestation; Large outbound exfiltration
- Top actions: Audit VM clone operations; Block attacker IP; Isolate compromised node
### SCENARIO_16_OIDC_SIGNING_KEY_THEFT
- Top signals: Forged tokens with abnormal lifetimes; Large outbound exfiltration; Privilege escalation via forged tokens
- Top actions: Audit token issuance; Block attacker IP; Disable IdP admin accounts
### SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE
- Top signals: Creation of rogue service principal; Cross-tenant secret access; Federated identity assuming privileged role
- Top actions: Audit role assumptions; Block attacker IP; Disable compromised identities
### SCENARIO_13_ZERO_DAY_EXPLOIT
- Top signals: Large outbound data transfer; Privilege escalation attempt; SSH lateral movement
- Top actions: Block attacker IP; Capture forensic artifacts; Disable vulnerable endpoint
### SCENARIO_12_SUPPLY_CHAIN_POISONING
- Top signals: Artifact hash mismatch; Malicious build step; Outbound callback to attacker
- Top actions: Audit pipeline history; Block attacker IP; Halt deployments
### SCENARIO_11_K8S_SIDECAR_BREAKOUT
- Top signals: Cloud API secret access; Host filesystem mount attempt; Kubelet client cert access
- Top actions: Audit cloud API calls; Isolate and drain node; Quarantine compromised pod
### SCENARIO_10_SERVICE_PRINCIPAL_HIJACK
- Top signals: Foreign IP service principal login; Large blob downloads; Long-lived secret creation
- Top actions: Audit IAM role changes; Block attacker IP; Disable service principal
### SCENARIO_4_BEC_ATTEMPT
- Top signals: Financial urgency keywords; New device fingerprint; Reply-to changed to external domain
- Top actions: Block suspicious IP; Disable executive account; Inspect mailbox rules
### SCENARIO_9_LATERAL_MOVEMENT_OAUTH
- Top signals: App impersonating multiple users; Large repo and mailbox exports; Long-lived refresh token
- Top actions: Audit app permission history; Block attacker IP; Disable OAuth app
### SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL
- Top signals: Device fingerprint mismatch; Impossible travel; Same token used from two locations
- Top actions: Block suspicious IP; Force MFA re-enrollment; Invalidate token
### SCENARIO_7_INSIDER_MISUSE
- Top signals: Access to sensitive finance files; High UEBA anomaly score; Large upload to personal cloud
- Top actions: Analyze ZIP contents; Block outbound uploads; Disable user account
### SCENARIO_6_VENDOR_COMPROMISE
- Top signals: AP team engagement; Changed banking details; Unusual vendor login region
- Top actions: Block vendor temporarily; Contact vendor security; Notify finance leadership
### SCENARIO_5_OAUTH_ABUSE
- Top signals: Foreign IP token use; High-risk scopes; Mailbox forwarding rule
- Top actions: Delete mailbox rules; Notify leadership; Remove malicious app
### SCENARIO_3_UNAUTHORIZED_ACCESS
- Top signals: Credential stuffing pattern; Multiple failed logins from rotating IPs; Sudden login success
- Top actions: Block suspicious IPs; Disable account; Enforce MFA
### SCENARIO_2_MALWARE_ATTACHMENT
- Top signals: Known test signature; Malware signature match; Quarantine event
- Top actions: Check whether similar messages bypassed filters; Confirm quarantine; Notify security team
### SCENARIO_1_SPAM_BURST
- Top signals: Authentication failures; Bot-like reconnect behavior; High-frequency inbound attempts
- Top actions: Block source IP; Increase rate-limit thresholds; Monitor for repeat attempts

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

## Incident Attack Graph

# Incident Attack Graph — 2026-04-14

This artifact defines the unified attack-surface ontology for all Mission Control scenarios and links every scenario into a single graph-based incident model.

## Graph Summary

- Scenario coverage: 17
- Node count: 57
- Edge count: 78
- Terminal scenario: SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE

## Node Types

- Scenario
- User
- Mailbox
- Session
- Identity Provider
- Federation Trust
- OAuth App
- Service Principal
- Device / Node
- Container / Pod
- VM / Workload
- Pipeline / Artifact
- Storage Bucket / Blob
- Network Endpoint
- TPM / Secure Enclave
- Hardware Attestation
- Attacker Infrastructure
- Event / Log Entry

## Relationship Types

- compromised_by
- issues_token_to
- assumes_role_in
- executes_on
- exfiltrates_to
- modifies
- creates_persistence_in
- moves_laterally_to
- forges_attestation_for
- extracts_key_from
- deploys_artifact_to
- encrypts
- spoofs_identity_of
- abused_by
- replayed_by
- signing_key_stolen_by
- targets
- observed_in
- validated_by

## Scenario-to-Graph Mapping

| Scenario | Layer | Risk | Primary Entities | Core Relationships |
|---|---|---|---|---|
| SCENARIO_1_SPAM_BURST | email-edge | Medium | mail-relay-01 | compromised_by (mail-relay-01 -> attacker-185.199.220.14) |
| SCENARIO_2_MALWARE_ATTACHMENT | email-edge | High | finance.user@example.com, finance.user@example.com | compromised_by (finance.user@example.com -> attacker-185.199.220.14) |
| SCENARIO_3_UNAUTHORIZED_ACCESS | identity | High | workstation-admin | compromised_by (workstation-admin -> attacker-185.199.220.14) |
| SCENARIO_4_BEC_ATTEMPT | identity | Critical | ceo-mailbox@example.com, ceo-mailbox@example.com | modifies (ceo-mailbox@example.com -> attacker-185.199.220.14); compromised_by (ceo-mailbox@example.com -> attacker-185.199.220.14) |
| SCENARIO_5_OAUTH_ABUSE | identity | High | rogue-consent-app, tenant-identity-plane | compromised_by (rogue-consent-app -> attacker-185.199.220.14); issues_token_to (tenant-identity-plane -> rogue-consent-app) |
| SCENARIO_6_VENDOR_COMPROMISE | supply-chain | Critical | vendor-automation-user, vendor-integration-gateway | compromised_by (vendor-automation-user -> attacker-185.199.220.14); targets (vendor-integration-gateway -> attacker-185.199.220.14) |
| SCENARIO_7_INSIDER_MISUSE | cloud | Critical | privileged.analyst@example.com, staging-bucket | exfiltrates_to (privileged.analyst@example.com -> staging-bucket); compromised_by (privileged.analyst@example.com -> attacker-185.199.220.14) |
| SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL | identity | Critical | dev-lead-primary, dev_lead@example.com | replayed_by (dev-lead-primary -> attacker-185.199.220.14); spoofs_identity_of (dev-lead-primary -> dev_lead@example.com) |
| SCENARIO_9_LATERAL_MOVEMENT_OAUTH | cloud | Critical | analyticssync, finance_lead@example.com, hr_manager@example.com | moves_laterally_to (analyticssync -> finance_lead@example.com); moves_laterally_to (analyticssync -> hr_manager@example.com); compromised_by (analyticssync -> attacker-185.199.220.14) |
| SCENARIO_10_SERVICE_PRINCIPAL_HIJACK | cloud | Critical | sp-prod-backup-manager, production-backup-plane | compromised_by (sp-prod-backup-manager -> attacker-185.199.220.14); executes_on (sp-prod-backup-manager -> production-backup-plane) |
| SCENARIO_11_K8S_SIDECAR_BREAKOUT | container | Critical | payments-sidecar, k8s-node-01 | moves_laterally_to (payments-sidecar -> k8s-node-01); compromised_by (payments-sidecar -> attacker-185.199.220.14) |
| SCENARIO_12_SUPPLY_CHAIN_POISONING | supply-chain | Critical | release-pipeline, malicious-build | deploys_artifact_to (malicious-build -> release-pipeline); compromised_by (release-pipeline -> attacker-185.199.220.14) |
| SCENARIO_13_ZERO_DAY_EXPLOIT | runtime | Critical | profile-api, db-admin-01 | compromised_by (profile-api -> attacker-185.199.220.14); moves_laterally_to (profile-api -> db-admin-01); creates_persistence_in (profile-api -> db-admin-01) |
| SCENARIO_14_HYBRID_CLOUD_RANSOMWARE | ransomware | Critical | fileserver-02, prod-app-01, customer-records | encrypts (fileserver-02 -> attacker-185.199.220.14); encrypts (prod-app-01 -> attacker-185.199.220.14); encrypts (customer-records -> attacker-185.199.220.14) |
| SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE | identity-federation | Critical | tenant-a-to-tenant-b, contractor_jane@tenantA.com, shadow-app | abused_by (tenant-a-to-tenant-b -> attacker-185.199.220.14); assumes_role_in (contractor_jane@tenantA.com -> tenant-a-to-tenant-b); creates_persistence_in (shadow-app -> tenant-a-to-tenant-b) |
| SCENARIO_16_OIDC_SIGNING_KEY_THEFT | identity-core | Critical | idp.example.com, ceo@example.com, finance_lead@example.com | signing_key_stolen_by (idp.example.com -> attacker-185.199.220.14); issues_token_to (idp.example.com -> ceo@example.com); moves_laterally_to (ceo@example.com -> finance_lead@example.com) |
| SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE | hardware-trust | Critical | node-7, node-7, node-7, prod-db-01, shadow-db | extracts_key_from (node-7 -> attacker-185.199.220.14); forges_attestation_for (node-7 -> shadow-db); spoofs_identity_of (shadow-db -> prod-db-01) |

## Conceptual Flow

- Attacker infrastructure compromises user, app, workload, pipeline, identity, and hardware surfaces across the full 17-scenario universe.
- Identity abuse escalates from credentials to OAuth, federation, and finally OIDC signing-key theft.
- Cloud and workload abuse expands through service principals, Kubernetes breakout, runtime compromise, ransomware, and hardware trust collapse.
- Hardware compromise in Scenario 17 invalidates the trust assumptions that software and cloud controls depend on.
- Mission Control should treat the graph as a single ontology whose terminal path ends at total identity, cloud, and hardware dominance.

## Mission Control Usage Notes

- Machine-readable graph: `incident_attack_graph.json`
- Human-readable graph map: `incident_attack_graph.md`
- Use scenario nodes as drill-down anchors and shared entity nodes as correlation pivots in visualizations.
- Use relationship frequency and criticality to rank likely blast-radius paths across identity, cloud, runtime, supply chain, and hardware trust layers.

## Red Team Deliverable Package

# Red Team Deliverable Package — 2026-04-14

This package defines campaign operating modes and formal red-team deliverables for Mission Control exercises.

## Campaign Modes

### One Scenario at a Time

- Mode: `one-scenario-at-a-time`
- Description: Run one scenario at a time for focused detection and response drills.
- Currently available scenarios: 17

### Multi-Scenario Chains

- Description: Run pre-defined chained campaigns for correlation and escalation analysis.
- Numeric shorthand example: 3 -> 5 -> 9 -> 14
- Example chain: SCENARIO_3_UNAUTHORIZED_ACCESS -> SCENARIO_5_OAUTH_ABUSE -> SCENARIO_9_LATERAL_MOVEMENT_OAUTH -> SCENARIO_14_HYBRID_CLOUD_RANSOMWARE
- Recommended chains:
  - SCENARIO_3_UNAUTHORIZED_ACCESS -> SCENARIO_5_OAUTH_ABUSE -> SCENARIO_9_LATERAL_MOVEMENT_OAUTH -> SCENARIO_14_HYBRID_CLOUD_RANSOMWARE
  - SCENARIO_5_OAUTH_ABUSE -> SCENARIO_10_SERVICE_PRINCIPAL_HIJACK -> SCENARIO_12_SUPPLY_CHAIN_POISONING -> SCENARIO_16_OIDC_SIGNING_KEY_THEFT
  - SCENARIO_11_K8S_SIDECAR_BREAKOUT -> SCENARIO_13_ZERO_DAY_EXPLOIT -> SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE

### Full-Spectrum Campaign

- Description: Run Scenario 1 through Scenario 20 in sequence as a simulated, synthetic, safe campaign.
- Numeric shorthand sequence: Scenario 1 -> 20 (simulated, synthetic, safe)
- Sequence policy: Scenario 1 -> Scenario 20 (simulated, synthetic, safe)
- Current sequence status:
  - 01. SCENARIO_1_SPAM_BURST [available]
  - 02. SCENARIO_2_MALWARE_ATTACHMENT [available]
  - 03. SCENARIO_3_UNAUTHORIZED_ACCESS [available]
  - 04. SCENARIO_4_BEC_ATTEMPT [available]
  - 05. SCENARIO_5_OAUTH_ABUSE [available]
  - 06. SCENARIO_6_VENDOR_COMPROMISE [available]
  - 07. SCENARIO_7_INSIDER_MISUSE [available]
  - 08. SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL [available]
  - 09. SCENARIO_9_LATERAL_MOVEMENT_OAUTH [available]
  - 10. SCENARIO_10_SERVICE_PRINCIPAL_HIJACK [available]
  - 11. SCENARIO_11_K8S_SIDECAR_BREAKOUT [available]
  - 12. SCENARIO_12_SUPPLY_CHAIN_POISONING [available]
  - 13. SCENARIO_13_ZERO_DAY_EXPLOIT [available]
  - 14. SCENARIO_14_HYBRID_CLOUD_RANSOMWARE [available]
  - 15. SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE [available]
  - 16. SCENARIO_16_OIDC_SIGNING_KEY_THEFT [available]
  - 17. SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE [available]
  - 18. SCENARIO_18_SYNTHETIC_PLACEHOLDER [synthetic_placeholder]
  - 19. SCENARIO_19_SYNTHETIC_PLACEHOLDER [synthetic_placeholder]
  - 20. SCENARIO_20_SYNTHETIC_PLACEHOLDER [synthetic_placeholder]

## 8) Red Team Deliverable Package

- Package name: Red Team Deliverable Package
- Deliverables:
  - Campaign scope and objectives
  - Scenario inject matrix
  - Unified incident attack graph
  - Detection and response checkpoints
  - Executive communication brief
  - Blue-team scoring workbook
  - After-action review template
  - Safety, legal, and control constraints

## Safety Controls

- No live malware deployment
- No unauthorized external network targeting
- No destructive commands against production systems
- Synthetic payloads and controlled telemetry only

## Campaign Launcher Manifest

# Campaign Launcher Manifest — 2026-04-14

Machine-runnable launcher profiles for Mission Control campaigns.

## Constraints

- safe_mode: True
- synthetic_only: True
- destructive_actions_forbidden: True
- authorized_scope_required: True

## Profiles

| ID | Mode | Safe | Synthetic | Sequence Length |
|---|---|---|---|---:|
| single-scenario_1_spam_burst | single_scenario | True | True | 1 |
| single-scenario_2_malware_attachment | single_scenario | True | True | 1 |
| single-scenario_3_unauthorized_access | single_scenario | True | True | 1 |
| single-scenario_4_bec_attempt | single_scenario | True | True | 1 |
| single-scenario_5_oauth_abuse | single_scenario | True | True | 1 |
| single-scenario_6_vendor_compromise | single_scenario | True | True | 1 |
| single-scenario_7_insider_misuse | single_scenario | True | True | 1 |
| single-scenario_8_token_replay_impossible_travel | single_scenario | True | True | 1 |
| single-scenario_9_lateral_movement_oauth | single_scenario | True | True | 1 |
| single-scenario_10_service_principal_hijack | single_scenario | True | True | 1 |
| single-scenario_11_k8s_sidecar_breakout | single_scenario | True | True | 1 |
| single-scenario_12_supply_chain_poisoning | single_scenario | True | True | 1 |
| single-scenario_13_zero_day_exploit | single_scenario | True | True | 1 |
| single-scenario_14_hybrid_cloud_ransomware | single_scenario | True | True | 1 |
| single-scenario_15_cross_tenant_federation_abuse | single_scenario | True | True | 1 |
| single-scenario_16_oidc_signing_key_theft | single_scenario | True | True | 1 |
| single-scenario_17_hardware_root_of_trust_compromise | single_scenario | True | True | 1 |
| chain-01 | multi_scenario_chain | True | True | 4 |
| chain-02 | multi_scenario_chain | True | True | 4 |
| chain-03 | multi_scenario_chain | True | True | 3 |
| full-spectrum-01 | full_spectrum_campaign | True | True | 20 |

## Example Launch Intents

- Single scenario: `python -m shadow_toolkit.cli campaign --mode single --scenario SCENARIO_3_UNAUTHORIZED_ACCESS`
- Chain campaign: `python -m shadow_toolkit.cli campaign --mode chain --chain-id chain-01`
- Full spectrum: `python -m shadow_toolkit.cli campaign --mode full-spectrum --start 1 --end 20 --safety simulated-synthetic-safe`

## Chain KPIs

# Chain KPI Report — 2026-04-14

- Scenario coverage: 17
- Critical scenarios: 13
- Avg signals/scenario: 5.29
- Avg actions/scenario: 5.82
- Highest signal density: SCENARIO_14_HYBRID_CLOUD_RANSOMWARE (7 signals)
- Avg dwell time (timeline-derived): 0.82 minutes
- Avg estimated response latency: 3.56 minutes
- Avg estimated containment latency: 4.38 minutes

## Estimated Response Latency by Scenario (Minutes)
- SCENARIO_10_SERVICE_PRINCIPAL_HIJACK: 5.0
- SCENARIO_11_K8S_SIDECAR_BREAKOUT: 8.0
- SCENARIO_12_SUPPLY_CHAIN_POISONING: 5.0
- SCENARIO_13_ZERO_DAY_EXPLOIT: 5.25
- SCENARIO_14_HYBRID_CLOUD_RANSOMWARE: 3.29
- SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE: 4.0
- SCENARIO_16_OIDC_SIGNING_KEY_THEFT: 3.0
- SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE: 3.0
- SCENARIO_1_SPAM_BURST: 2.0
- SCENARIO_2_MALWARE_ATTACHMENT: 2.0
- SCENARIO_3_UNAUTHORIZED_ACCESS: 5.0
- SCENARIO_4_BEC_ATTEMPT: 2.0
- SCENARIO_5_OAUTH_ABUSE: 2.0
- SCENARIO_6_VENDOR_COMPROMISE: 5.0
- SCENARIO_7_INSIDER_MISUSE: 2.0
- SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL: 2.0
- SCENARIO_9_LATERAL_MOVEMENT_OAUTH: 2.0

## Dwell Time by Scenario (Minutes)
- SCENARIO_10_SERVICE_PRINCIPAL_HIJACK: 0
- SCENARIO_11_K8S_SIDECAR_BREAKOUT: 0
- SCENARIO_12_SUPPLY_CHAIN_POISONING: 0
- SCENARIO_13_ZERO_DAY_EXPLOIT: 3
- SCENARIO_14_HYBRID_CLOUD_RANSOMWARE: 3
- SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE: 2
- SCENARIO_16_OIDC_SIGNING_KEY_THEFT: 3
- SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE: 3
- SCENARIO_1_SPAM_BURST: 0
- SCENARIO_2_MALWARE_ATTACHMENT: 0
- SCENARIO_3_UNAUTHORIZED_ACCESS: 0
- SCENARIO_4_BEC_ATTEMPT: 0
- SCENARIO_5_OAUTH_ABUSE: 0
- SCENARIO_6_VENDOR_COMPROMISE: 0
- SCENARIO_7_INSIDER_MISUSE: 0
- SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL: 0
- SCENARIO_9_LATERAL_MOVEMENT_OAUTH: 0

## Estimated Containment Latency by Scenario (Minutes)
- SCENARIO_10_SERVICE_PRINCIPAL_HIJACK: 5.0
- SCENARIO_11_K8S_SIDECAR_BREAKOUT: 8.0
- SCENARIO_12_SUPPLY_CHAIN_POISONING: 5.0
- SCENARIO_13_ZERO_DAY_EXPLOIT: 8.25
- SCENARIO_14_HYBRID_CLOUD_RANSOMWARE: 6.29
- SCENARIO_15_CROSS_TENANT_FEDERATION_ABUSE: 6.0
- SCENARIO_16_OIDC_SIGNING_KEY_THEFT: 6.0
- SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE: 6.0
- SCENARIO_1_SPAM_BURST: 2.0
- SCENARIO_2_MALWARE_ATTACHMENT: 2.0
- SCENARIO_3_UNAUTHORIZED_ACCESS: 5.0
- SCENARIO_4_BEC_ATTEMPT: 2.0
- SCENARIO_5_OAUTH_ABUSE: 2.0
- SCENARIO_6_VENDOR_COMPROMISE: 5.0
- SCENARIO_7_INSIDER_MISUSE: 2.0
- SCENARIO_8_TOKEN_REPLAY_IMPOSSIBLE_TRAVEL: 2.0
- SCENARIO_9_LATERAL_MOVEMENT_OAUTH: 2.0

