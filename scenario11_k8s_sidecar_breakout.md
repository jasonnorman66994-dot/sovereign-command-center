# Scenario 11 — Kubernetes Sidecar Compromise + Container Breakout

## Overview

An attacker compromises a vulnerable application container, pivots into the security sidecar, escapes to the node, and then uses the node’s credentials to access cloud APIs. This scenario tests detection and response across:

- Pod-level telemetry
- Sidecar behavior
- Node-level privilege boundaries
- Lateral movement inside the cluster
- Cloud-API abuse after breakout

## Input Evidence Bundle

1. **Initial Compromise (App Container)**
   - Unauthorized exec into container without API server
2. **Sidecar Tampering**
   - Unexpected binary execution, file integrity diff
3. **Privilege Escalation Attempt**
   - SYS_ADMIN capability, host filesystem mount
4. **Node-Level Breakout**
   - Access to kubelet client cert
5. **Cloud API Abuse (Post-Breakout)**
   - Node credentials used to access cloud secrets
6. **Cluster-Wide Recon**
   - Node identity used to enumerate pods and secrets
7. **UEBA Output**
   - High anomaly score for breakout, secret access, lateral movement

## Key Detection Signals

- Unauthorized exec into container
- Sidecar integrity violations
- Suspicious script execution
- SYS_ADMIN escalation
- Host filesystem mount attempt
- Kubelet client cert access
- Cloud API secret access
- Lateral movement, credential harvesting

## Expected Classification

Kubernetes Container Breakout → Node Compromise → Cloud API Abuse

## SOC Actions

- Quarantine compromised pod
- Isolate and drain node
- Rotate kubelet certificates
- Revoke node IAM credentials
- Audit cloud API calls
- Rebuild node from clean image
- Enforce read-only root filesystem
- Implement workload identity with short-lived tokens
- Add syscall-level detection (seccomp, AppArmor)
- Harden kubelet authentication

## Timeline

| Time   | Event                                      |
|--------|--------------------------------------------|
| 18:12  | K8s Sidecar Breakout + Node Compromise     |

## Analyst Guidance

This scenario requires correlating pod, sidecar, node, and cloud telemetry. Look for privilege escalation, credential harvesting, and lateral movement. Immediate containment and credential rotation are critical.
