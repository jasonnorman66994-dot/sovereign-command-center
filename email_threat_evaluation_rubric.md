# Email Threat Detection — Graded Evaluation Rubric (v1.0)

A production-grade scoring framework for SOC analyst onboarding, agent scoring, and automated assessment pipelines.

## Scoring Overview

| Dimension              | Weight | Description                                      |
|------------------------|--------|--------------------------------------------------|
| Threat Identification  | 25%    | Did the agent correctly identify the threat type? |
| Signal Recognition     | 25%    | Did the agent detect the key indicators in logs?  |
| Recommended Actions    | 25%    | Were remediation steps correct and prioritized?   |
| Risk Assessment        | 15%    | Did the agent understand severity/impact?         |
| Clarity & Structure    | 10%    | Was the response organized and SOC-ready?         |

Total Score = 100 points

---

### Dimension-Level Scoring Criteria

#### 1. Threat Identification (25 pts)
| Score | Criteria |
|-------|----------|
| 25    | Exact, correct classification (e.g., “BEC – active account takeover”). |
| 20    | Mostly correct but slightly broad (e.g., “account compromise”). |
| 10    | Vague or partially incorrect classification. |
| 0     | Incorrect or missing classification. |

#### 2. Signal Recognition (25 pts)
| Score | Criteria |
|-------|----------|
| 25    | Identifies all critical signals and explains why. |
| 20    | Identifies most signals but misses one important indicator. |
| 10    | Identifies only surface-level signals. |
| 0     | Misses the signals entirely. |

#### 3. Recommended Actions (25 pts)
| Score | Criteria |
|-------|----------|
| 25    | Complete, prioritized, SOC-grade action plan. |
| 20    | Correct actions but missing one or two steps. |
| 10    | Generic or incomplete actions. |
| 0     | Incorrect or unsafe actions. |

#### 4. Risk Assessment (15 pts)
| Score | Criteria |
|-------|----------|
| 15    | Accurately assesses severity and business impact. |
| 10    | Reasonable but lacks nuance. |
| 5     | Minimal risk interpretation. |
| 0     | No risk assessment or incorrect. |

#### 5. Clarity & Structure (10 pts)
| Score | Criteria |
|-------|----------|
| 10    | Clear, structured, concise, SOC-ready. |
| 7     | Mostly clear but slightly verbose. |
| 3     | Hard to follow or poorly organized. |
| 0     | Unusable or incoherent. |

---

### Final Score Calculation

Final Score = sum(Dimension Score × Weight)

---

### Scenario Benchmarks

| Scenario                | Expected Classification                | Passing Score | Critical Signals |
|-------------------------|----------------------------------------|---------------|-----------------|
| Spam Burst              | Spam burst / relay probing             | ≥ 70          | repeated attempts, relay denial, auth failures |
| Malware Attachment      | Malware attachment attempt             | ≥ 75          | signature match, quarantine, sender identity   |
| Unauthorized Access     | Credential compromise                  | ≥ 80          | IP rotation, failed logins, sudden success     |
| BEC                     | Business Email Compromise (takeover)   | ≥ 90          | new device, reply-to change, mailbox rules, financial language |

BEC is graded most strictly due to its impact.
