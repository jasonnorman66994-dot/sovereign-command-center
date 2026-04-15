# Scenario 16 - Global Identity Provider Compromise via OIDC Signing Key Theft

## Overview

An attacker compromises the global identity provider and steals the OIDC signing key material used to sign tokens trusted across internal applications, cloud control planes, SaaS providers, and partner-facing services. Once the attacker controls the signing keys, every forged token validates successfully, every downstream signature check passes, and the identity fabric can no longer distinguish legitimate sessions from attacker-minted access.

This scenario spans:

- IdP administrative access and MFA bypass telemetry
- Unauthorized access to the OIDC keystore and signing key export
- Policy-violating but cryptographically valid forged tokens
- Privileged role assumption through forged identity artifacts
- Cross-service cloud and SaaS impersonation activity
- Rogue signing-key creation for persistence
- Massive exfiltration after total identity trust collapse

## Input Evidence Bundle

1. **Suspicious IdP Admin Activity**
   - `idp-admin` logs into `idp-core` from attacker IP `185.199.220.14`.
   - MFA is bypassed under a `trusted device` condition that should not apply.
2. **Unauthorized Export of OIDC Signing Keys**
   - The keystore exports `oidc-signing-key-01` in `pem` format.
   - The export is not linked to an approved change or key-management workflow.
3. **Forged Tokens Start Validating**
   - `ceo@example.com` presents a token with issuer `idp.example.com` from an unknown device.
   - The token lifetime is `48h`, exceeding normal policy constraints while still validating cryptographically.
4. **Privilege Escalation Through Forged Tokens**
   - A forged token is used to assume the `GlobalAdmin` role via OIDC.
   - The role assumption occurs without the interactive MFA path normally required.
5. **Lateral Movement Across Cloud and SaaS**
   - The attacker enumerates mailboxes and downloads `finance_lead@example.com` mailbox contents.
   - Multiple services now trust attacker-issued identities because the IdP itself is compromised.
6. **Persistence Through Rogue Signing Material**
   - A rogue key named `oidc-signing-key-evil` is created with a `5 years` lifetime.
   - The key is excluded from the normal rotation schedule to preserve long-term attacker access.
7. **Global Exfiltration**
   - `12.4 GB` of outbound traffic leaves the environment for `185.199.220.14`.

## Key Detection Signals

- IdP admin login from a suspicious external IP
- MFA bypass via an abused `trusted device` flag
- Unauthorized export of OIDC signing keys
- Token validation events that violate token lifetime or issuance policy
- Privileged role assumption without the expected MFA chain
- Multi-user impersonation across cloud and SaaS services
- Rogue signing key creation outside rotation policy
- Large outbound transfer to attacker infrastructure seen in prior scenarios

## Expected Classification

Global Identity Provider Compromise - OIDC Signing Key Theft

## SOC Actions

- Rotate all OIDC signing keys immediately
- Invalidate all issued tokens globally
- Disable IdP admin accounts and suspicious administrative sessions
- Block attacker IP and associated egress paths
- Force re-authentication across all federated applications and tenants
- Audit all token issuance and privileged role assumption activity
- Review IdP admin session logs and the initial compromise vector
- Remove rogue signing keys and rebuild the IdP from a clean state
- Implement hardware-backed key protection and stricter admin MFA controls
- Coordinate leadership, legal, compliance, and external communications for trust reset

## Timeline

| Time  | Event |
|-------|-------|
| 23:12 | Attacker logs into the IdP admin plane from a suspicious IP and bypasses MFA using a trusted-device path |
| 23:12 | OIDC signing key `oidc-signing-key-01` is exported without approved change control |
| 23:13 | Forged but valid tokens appear with abnormal lifetimes and are used to assume `GlobalAdmin` |
| 23:14 | Cloud and SaaS impersonation expands across executive and finance identities |
| 23:14 | Rogue signing key creation establishes long-term persistence outside rotation policy |
| 23:15 | Large outbound transfer confirms mass data theft after identity trust collapse |

## Analyst Guidance

Treat this as full identity-plane compromise, not account takeover. The attacker is no longer abusing trust; the attacker now controls the trust anchor itself. Prioritize global token invalidation, key rotation, trust-boundary isolation, and full reconstruction of identity assurance. Focus investigations on keystore access, forged-token usage patterns, rogue key propagation, privileged impersonation across services, and the initial path that led to IdP administrative compromise.
