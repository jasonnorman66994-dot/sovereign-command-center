# Scenario 8 Detection Heatmap

## Overview

This artifact provides an hour-by-hour concentration view of red-flag activity for Scenario 8 entities. It is intended to help analysts identify peak periods and repeatedly flagged users for triage prioritization.

## Input Evidence Bundle

### Hourly User Red-Flag Counts

| Hour | User | Red Flag Count |
|------|------|----------------|
| 00 | svc_backup@enterprise.com | 2 |
| 01 | user_201@enterprise.com | 3 |
| 02 | user_202@enterprise.com | 3 |
| 03 | svc_automation@enterprise.com | 2 |
| 03 | user_203@enterprise.com | 1 |
| 04 | user_204@enterprise.com | 3 |
| 05 | user_205@enterprise.com | 3 |
| 07 | user_207@enterprise.com | 3 |
| 08 | user_208@enterprise.com | 2 |
| 12 | user_212@enterprise.com | 2 |
| 13 | svc_hr@enterprise.com | 1 |
| 15 | user_214@enterprise.com | 3 |

## Key Detection Signals

- Repeated high red-flag counts for individual users
- Clustered detection bursts at specific hours
- Service-account participation in anomalous patterns

## Expected Classification

Scenario 8 Supporting Artifact - Detection Concentration Heatmap

## SOC Actions

- Prioritize investigation of users with 3 red flags
- Correlate peak hours with authentication and data-access logs
- Validate service-account behavior against expected automation jobs

## Timeline

| Time Window | Event |
|-------------|-------|
| 00-03 | Early anomalies begin across service and user identities |
| 04-08 | Sustained high-risk concentration among repeated user entities |
| 12-15 | Additional midday spikes confirm recurring detection pattern |

## Analyst Guidance

Use this heatmap as triage context rather than standalone evidence. Pair it with Scenario 8 raw logs and UEBA outputs to determine whether repeated flags represent coordinated malicious behavior or benign operational overlap.
