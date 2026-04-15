# Scenario 10 - Cloud Workload Compromise (Service Principal Hijack)

## Overview

An attacker hijacks a cloud service principal and expands access through IAM abuse, compute manipulation, large data extraction, and credential persistence. Detection relies on identity, control-plane, workload, and storage telemetry correlation.

## Input Evidence Bundle

### 1. Suspicious Credential Use

```text
Apr 14 17:22:10 cloudapi[4411]: SERVICE PRINCIPAL LOGIN spn="ci-deploy-agent" method="client_secret" ip=185.199.220.14
Apr 14 17:22:11 cloudapi[4411]: WARNING: Secret used is older than 400 days
```

### 2. Privilege Escalation Attempt

```text
Apr 14 17:23:44 iam[7712]: ROLE ASSIGNMENT spn="ci-deploy-agent" role="Contributor" scope="/subscriptions/prod"
Apr 14 17:23:45 iam[7712]: WARNING: SPN attempted to assign itself a new role
```

### 3. Lateral Movement Across Cloud Resources

```text
Apr 14 17:24:10 compute[8821]: VM LIST spn="ci-deploy-agent" region="us-east-1"
Apr 14 17:24:11 compute[8821]: VM START spn="ci-deploy-agent" vm="analytics-runner-03"
Apr 14 17:24:12 compute[8821]: VM EXTENSION INSTALL spn="ci-deploy-agent" extension="custom-script" payload="download_and_execute.sh"
```

### 4. Data Exfiltration Behavior

```text
Apr 14 17:25:55 storage[5512]: BLOB DOWNLOAD spn="ci-deploy-agent" container="prod-secrets" size=3.4GB
Apr 14 17:25:56 storage[5512]: BLOB DOWNLOAD spn="ci-deploy-agent" container="customer-records" size=8.1GB
```

### 5. Persistence Mechanism

```text
Apr 14 17:26:10 iam[7712]: NEW SECRET CREATED spn="ci-deploy-agent" secret_id="secret-9981" lifetime="2 years"
```

### 6. UEBA Output

```text
Apr 14 17:26:30 ueba[9911]: anomaly_score=9.9 entity="ci-deploy-agent" reason="privilege escalation + VM manipulation + secret creation + large data exfiltration"
```

## Key Detection Signals

- Detect foreign IP service principal logins
- Detect use of old secrets
- Detect unauthorized role assignment attempts
- Detect VM enumeration, starts, and extension installs
- Detect large blob downloads
- Detect long-lived secret creation
- Detect high UEBA anomaly scores

## Expected Classification

Cloud Workload Compromise - Service Principal Hijack

## SOC Actions

- Disable the service principal
- Revoke secrets and tokens
- Block the attacker IP
- Stop the malicious VM and remove extensions
- Audit IAM role changes
- Rotate all workload secrets

## Example SQL for Dashboard/Detection

```sql
-- Foreign IP SPN login
SELECT * FROM cloudapi WHERE event LIKE '%SERVICE PRINCIPAL LOGIN%' AND ip NOT LIKE '10.%' AND ip NOT LIKE '192.168.%';
-- Old secret used
SELECT * FROM cloudapi WHERE event LIKE '%Secret used is older than%' AND event LIKE '%400 days%';
-- Unauthorized role assignment
SELECT * FROM iam WHERE event LIKE '%SPN attempted to assign itself%';
-- VM manipulation
SELECT * FROM compute WHERE event LIKE '%VM EXTENSION INSTALL%' OR event LIKE '%VM START%';
-- Large blob downloads
SELECT * FROM storage WHERE event LIKE '%BLOB DOWNLOAD%' AND size > 1000;
-- Long-lived secret creation
SELECT * FROM iam WHERE event LIKE '%NEW SECRET CREATED%' AND lifetime > 365;
-- High UEBA anomaly
SELECT * FROM ueba WHERE anomaly_score > 9.0;
```

## Training Drill

1. Review `cloudapi`, `iam`, `compute`, `storage`, and `ueba` logs for service-principal hijack and lateral movement.
2. Use dashboard panels to visualize.
3. Practice SOC response steps as above.

## Timeline

| Time  | Event |
|-------|-------|
| 17:22 | Service principal login occurs from suspicious external IP using stale secret |
| 17:23 | Principal attempts self-assigned privilege escalation |
| 17:24 | Compute resources are enumerated and script extension deployed |
| 17:25 | Large blob downloads begin across sensitive containers |
| 17:26 | New long-lived secret is created and UEBA anomaly peaks |

## Analyst Guidance

Treat this as identity-to-workload pivot compromise. Prioritize principal disablement, secret/token revocation, VM extension rollback, and blast-radius scoping across all resources recently accessed by the principal.
