# Scenario 14 - Ransomware Detonation in Hybrid Cloud

## Overview

An attacker who has already moved quietly through the environment triggers a coordinated ransomware payload across on-prem servers, cloud VMs, Kubernetes workloads, and object storage. This is a full-scale hybrid-cloud encryption event with destructive impact across identity, compute, storage, and runtime surfaces.

This scenario spans:

- On-prem endpoint and EDR telemetry
- Identity and Kerberos abuse
- Cloud VM behavior
- Kubernetes runtime destruction
- Object storage encryption patterns
- Command-and-control validation

## Input Evidence Bundle

1. **Initial Indicators (On-Prem)**
   - `encryptor.exe` launched on `fileserver-02` from `svchost.exe`, signed by an untrusted certificate.
2. **Lateral Movement (On-Prem to Cloud)**
   - `svc-backup` uses a Kerberos TGT consistent with golden ticket activity.
3. **Cloud VM Encryption**
   - `prod-app-01` shows mass file modification and sustained 100% CPU.
4. **Kubernetes Workload Impact**
   - `payments-api` deletes application data and attempts to overwrite the root filesystem.
5. **Cloud Storage Encryption**
   - `customer-records` bucket rewrites objects from `*.bak` to `*.locked` at extreme volume.
6. **Ransom Note Deployment**
   - `/etc/motd` overwritten with a ransom note.
7. **Command-and-Control Beacon**
   - Small outbound `/status` beacon to the attacker IP.

## Key Detection Signals

- Untrusted binary execution with suspicious parent process
- Golden ticket style Kerberos activity
- Mass file encryption patterns on cloud VMs
- Kubernetes data destruction and root filesystem tampering
- Object storage rewrite surge beyond baseline
- Ransom note deployment
- Outbound C2 beacon to attacker infrastructure

## Expected Classification

Coordinated Hybrid-Cloud Ransomware Detonation

## SOC Actions

- Isolate affected on-prem servers
- Quarantine impacted cloud VMs
- Block attacker IP and sinkhole C2 traffic
- Disable compromised service accounts and halt deployments/backups
- Capture memory and disk artifacts
- Review Kerberos ticket issuance and initial intrusion path
- Restore from offline backups
- Rotate all credentials and rebuild compromised nodes
- Activate leadership, legal, and customer communication workflows

## Timeline

| Time  | Event |
|-------|-------|
| 21:12 | Hybrid-cloud ransomware detonation begins on on-prem file server |
| 21:13 | Golden ticket pivot and cross-environment encryption spread confirmed |
| 21:14 | Object storage locking and ransom note deployment escalate incident |
| 21:15 | C2 beacon confirms detonation success and triggers full executive escalation |

## Analyst Guidance

Treat this as the worst-day hybrid-cloud event: not a single-host infection and not opportunistic malware. Correlate identity abuse, encryption behavior, storage rewrite anomalies, Kubernetes destruction, and command-and-control validation to scope the full blast radius and drive immediate containment.
