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
