# Scenario 12 — Supply-Chain Poisoning (CI/CD Pipeline Compromise)

## Overview

An attacker compromises the CI/CD pipeline by injecting a malicious build step into a shared pipeline template. Poisoned artifacts are deployed to staging and production, with embedded credential harvesters and backdoor callbacks. This scenario spans:

- Source control
- Build pipeline
- Artifact registry
- Deployment system
- Runtime telemetry

## Input Evidence Bundle

1. **Unauthorized Commit to Pipeline Template**
   - Automation bot impersonation, unknown GPG signature
2. **Malicious Build Step Inserted**
   - Remote script execution in CI
3. **Build Pipeline Execution**
   - Malicious step executed successfully
4. **Artifact Registry Poisoning**
   - Artifact hash mismatch, unexpected change
5. **Deployment to Staging and Production**
   - Poisoned artifact deployed
6. **Runtime Callback from Compromised Service**
   - Outbound connection to attacker
7. **Credential Harvesting Behavior**
   - Secret harvesting, unexpected file access

## Key Detection Signals

- Unauthorized commit to pipeline template
- Unknown GPG signature
- Malicious build step
- Artifact hash mismatch
- Outbound callback to attacker
- Secret harvesting behavior

## Expected Classification

Supply-Chain Compromise — CI/CD Pipeline Poisoning

## SOC Actions

- Halt all deployments
- Revoke automation-bot credentials
- Block attacker IP
- Roll back to last known-good artifact
- Audit pipeline history
- Rebuild CI/CD environment
- Rotate all secrets accessed by compromised service
- Enforce signed commits + verified GPG keys
- Add runtime egress restrictions
- Implement pipeline integrity monitoring

## Timeline

| Time   | Event                              |
|--------|------------------------------------|
| 19:12  | CI/CD Pipeline Poisoning           |

## Analyst Guidance

This scenario requires correlating source control, CI/CD, artifact, deployment, and runtime telemetry. Look for impersonation, pipeline tampering, artifact poisoning, and runtime callbacks. Immediate containment and credential rotation are critical.
