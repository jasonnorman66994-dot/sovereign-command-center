# Scenario 8 Detection Summary Dashboard

## Overview

This dashboard summary condenses Scenario 8 detection outcomes into response-level KPIs. It supports rapid leadership visibility into detection effectiveness, risk distribution, and automated containment posture.

## Input Evidence Bundle

### Detection Rates

- Total log lines: 24
- Threats detected: 12
- Detection rate: 50%

### Risk Score Distribution

- Critical (>0.85): 7
- High (0.60–0.85): 3
- Medium (0.30–0.60): 2
- Low (<0.30): 12

### Automated Actions

- Accounts locked: 7
- MFA challenges: 3
- Flagged for review: 2

### Top Users by Red Flags

- user_201@enterprise.com: 3
- user_202@enterprise.com: 3
- user_204@enterprise.com: 3
- user_205@enterprise.com: 3
- user_207@enterprise.com: 3
- user_214@enterprise.com: 3

## Key Detection Signals

- High critical-risk concentration relative to total detections
- Strong automated response activation across lock and MFA controls
- Repeat-flag user cluster requiring focused analyst review

## Expected Classification

Scenario 8 Supporting Artifact - Detection Summary KPI Dashboard

## SOC Actions

- Escalate all critical detections for immediate validation
- Confirm locked-account and MFA actions were applied successfully
- Perform targeted review of repeatedly flagged users and related sessions

## Timeline

| Phase | Event |
|-------|-------|
| Ingest | 24 total log entries processed |
| Detect | 12 threats identified across risk tiers |
| Respond | 7 account locks and 3 MFA challenges executed |
| Review | 2 detections queued for analyst follow-up |

## Analyst Guidance

Use these KPI values to drive operational prioritization, then pivot into underlying event logs for root-cause validation and false-positive reduction analysis.
