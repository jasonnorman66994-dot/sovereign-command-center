# Scenario 15 - Cross-Tenant Cloud Takeover via Federation Abuse

## Overview

An attacker compromises a federated identity provider in Tenant A, then abuses that trust path to impersonate privileged roles in Tenant B. Because the resulting federation tokens are valid and cryptographically signed, the activity initially looks legitimate unless defenders correlate issuer anomalies, privileged role assumptions, secret access, rogue trust creation, and outbound transfer behavior across both tenants.

This scenario spans:

- Federation token issuance telemetry in Tenant A
- Cross-tenant IAM role assumption in Tenant B
- Cloud directory and API abuse in Tenant B
- Secret and storage access anomalies
- Rogue trust and persistence creation
- Cross-tenant exfiltration and UEBA escalation

## Input Evidence Bundle

1. **Federation Token Issuance from Compromised Tenant A**
   - `contractor_jane@tenantA.com` receives a federation token for `tenantB.com` from an unknown device fingerprint `DF-9912`.
2. **Cross-Tenant Privilege Escalation in Tenant B**
   - The federated identity assumes `TenantB-GlobalAdmin`, a role not normally granted to federated users.
3. **Cloud API Abuse and Persistence Seeding**
   - The attacker enumerates users and creates a high-privilege service principal named `shadow-app` with `Directory.ReadWrite.All`.
4. **Secret Access and Lateral Movement**
   - The federated identity downloads 4.8 GB from the restricted `prod-secrets` container.
5. **Rogue Federation Persistence**
   - A new federation trust is created with issuer `shadow-app` and no admin approval.
6. **Cross-Tenant Exfiltration**
   - A 6.2 GB outbound transfer is observed from Tenant B to attacker infrastructure at `185.199.220.14`.
7. **UEBA Confirmation**
   - UEBA scores the entity at `10.0` for cross-tenant privilege escalation, secret access, and federation abuse.

## Key Detection Signals

- Suspicious federation token issuance from a compromised external tenant
- Unknown device fingerprint tied to a federated identity
- Federated identity assuming a privileged global admin role
- Directory enumeration and creation of a rogue high-privilege service principal
- Access to restricted secrets and storage from a federated user
- Unauthorized creation of a new federation trust
- Large outbound exfiltration to attacker infrastructure

## Expected Classification

Cross-Tenant Cloud Takeover - Federation Abuse

## SOC Actions

- Disable federation trust between Tenant A and Tenant B
- Revoke all active federation tokens
- Block attacker IP and associated egress paths
- Disable compromised identities in both tenants
- Audit cross-tenant role assumptions and privileged changes
- Review federation token issuance and initial compromise path in Tenant A
- Remove rogue service principals and trust objects such as `shadow-app`
- Rotate all secrets accessed during the intrusion
- Rebuild federation trust with strict approval and conditional access controls

## Timeline

| Time  | Event |
|-------|-------|
| 22:12 | Compromised Tenant A issues a federation token for Tenant B from an unknown device |
| 22:12 | Tenant B grants federated identity access to a global admin role outside normal policy |
| 22:13 | Directory enumeration, service principal creation, and restricted secret access confirm active takeover |
| 22:14 | Rogue federation trust creation establishes persistence and outbound transfer confirms cross-tenant exfiltration |

## Analyst Guidance

Treat this as a federation-tier cloud identity breach, not a single-tenant IAM mistake. Correlate issuer drift, device fingerprint anomalies, unexpected external role assumptions, high-privilege API changes, trust creation, and outbound transfer behavior to scope both the identity control plane compromise and the data impact across tenants.
