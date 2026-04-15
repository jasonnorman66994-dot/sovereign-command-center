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
