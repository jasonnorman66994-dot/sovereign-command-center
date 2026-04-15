# Scenario 17 - Hardware Root-of-Trust Compromise via TPM / Secure Enclave Extraction

## Overview

An attacker reaches below the operating system and compromises the hardware trust anchor on `node-7`, extracting secrets from a TPM or Secure Enclave that upstream workload identity, disk encryption, attestation, and measured-boot assurances all depend on. Once the hardware root of trust is compromised, the attacker can forge health signals, decrypt protected volumes, impersonate trusted workloads, and persist beneath the software stack.

This scenario spans:

- Unauthorized low-level TPM access and PCR inspection
- Secure Enclave debug abuse and memory-dump attempts
- Raw export of protected key material
- Forged attestation that contradicts measured boot state
- VM cloning with decrypted storage keys
- Workload identity bypass using forged attestation
- Large-scale exfiltration from cloned or impersonated workloads

## Input Evidence Bundle

1. **Suspicious Low-Level Access**
   - An unapproved process reads PCR state from the TPM on `node-7`.
2. **Secure Enclave Memory Extraction Attempt**
   - An unauthorized enclave debug session opens and requests a memory dump.
3. **Private Key Extraction**
   - The TPM exports `vm-disk-key` in raw format despite a deny policy.
4. **Attestation Forgery**
   - A health report is generated for `node-7`, but the PCR values no longer match the boot log.
5. **Disk Decryption and VM Impersonation**
   - The attacker clones `prod-db-01` into `shadow-db` using the stolen disk decryption key.
6. **Cloud API Abuse via Forged Attestation**
   - `shadow-db` receives trusted workload access because forged attestation is accepted.
7. **Sensitive Data Exfiltration**
   - `9.4 GB` of data leaves the environment for `185.199.220.14`.

## Key Detection Signals

- Unauthorized TPM access and PCR reads by a non-allowlisted process
- Secure Enclave debug or memory-dump activity
- Raw key export that bypasses TPM or enclave policy
- Attestation reports inconsistent with boot measurements
- VM cloning that depends on extracted disk-protection keys
- Trusted workload access granted from forged attestation
- Large outbound transfer to attacker infrastructure seen in earlier scenarios

## Expected Classification

Hardware Root-of-Trust Compromise - TPM/Secure Enclave Extraction

## SOC Actions

- Isolate `node-7` from the cluster immediately
- Revoke attestation-based trust for affected workloads
- Rotate all keys protected by the TPM or enclave
- Block attacker IP and associated egress paths
- Capture TPM event logs, PCR history, and enclave debug traces
- Review VM clone and shadow workload creation activity
- Identify the initial foothold that led to hardware access
- Rebuild `node-7` from a clean hardware-backed image
- Replace TPM or secure enclave hardware if compromise cannot be ruled out
- Enforce remote attestation verification and stricter low-level access controls

## Timeline

- `00:12` Non-allowlisted process reads TPM PCR state and opens an unauthorized enclave debug session.
- `00:13` Raw export of `vm-disk-key` confirms hardware-backed key material has been extracted.
- `00:13` Forged attestation report claims healthy state despite PCR and boot-log mismatch.
- `00:14` `prod-db-01` is cloned into `shadow-db` using the stolen disk key and trusted-attestation bypass.
- `00:15` Large outbound transfer confirms exfiltration from the cloned or impersonated workload.

## Analyst Guidance

Treat this as the collapse of the deepest trust boundary in the environment. Software telemetry above the hardware layer is no longer sufficient on its own because the attacker can forge attestation and impersonate trusted workloads. Prioritize hardware log capture, key rotation, attestation trust revocation, and validation that no cloned workload or boot-path artifact remains trusted after containment.
