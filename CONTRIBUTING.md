# Contributing Guide

## Development Workflow

1. Pull latest changes from `main`.
2. Create a feature branch.
3. Make changes in small, reviewable commits.
4. Run local validation before opening a PR.

## Local Quality Gates

Use the smoke check script to validate changes:

```powershell
powershell -ExecutionPolicy Bypass -File .\smoke_check.ps1 -Mode Quick
powershell -ExecutionPolicy Bypass -File .\smoke_check.ps1 -Mode Full
```

Mode behavior:

- `Quick`: scenario and timeline markdown lint + Python syntax checks.
- `Full`: wider curated markdown lint scope + Python syntax checks.

## Phase 2 Telemetry Validation

Run the synthetic harness after telemetry or notification changes:

```powershell
python scripts/phase2_telemetry_harness.py
```

Pass criteria:

- `Events consumed: 2`
- `DB rows delta (phase2 modules): 2`
- `Notification calls: slack=2, email=1, telegram=1`
- `RESULT: PASS`

If the first run fails with `Events consumed: 0`, run the harness once more.

Manual CI job:

- GitHub Actions -> `Telemetry Harness` -> `Run workflow`

## Scenario Analysis & Reporting

### Creating Scenario Event Files

Add synthetic event files to support attack chain timeline analysis:

```json
[
  {
    "event": "email_spam_burst",
    "count": 150,
    "source": "attacker@example.com",
    "timestamp": "2026-04-15T12:01:00Z"
  },
  {
    "event": "privilege_escalation_attempt",
    "account": "admin-service",
    "timestamp": "2026-04-15T12:05:00Z"
  }
]
```

File naming: `scenario{N}_events.json` where N is the scenario number.

### Updating ATT&CK Heatmap Dataset

When adding or modifying scenarios, update `data/unified_mitre_heatmap.json`:

```json
{
  "tactic": "Initial Access",
  "technique": "Phishing / Spam Burst",
  "technique_id": "T1566",
  "scenarios": [10, 11, 13]
}
```

Run the generator to produce updated report:

```powershell
python generate_unified_mitre_heatmap.py
```

### Leadership Report

The consolidated leadership report (`leadership_attack_coverage_timeline_report.md`) is manually maintained. Update when:

- New scenarios are added to the main corpus
- ATT&CK coverage profile changes significantly
- Timeline narratives need revision for clarity

## Git Hooks

Repository-local hooks are enabled via `core.hooksPath=.githooks`.

- `pre-commit` runs Quick mode.
- `pre-push` runs Full mode.

Run manually for troubleshooting:

```powershell
git hook run pre-commit
git hook run pre-push
```

## CI Quality Gates

GitHub Actions workflow: `.github/workflows/quality-gates.yml`

- Pull requests to `main` run Quick mode.
- Pushes to `main` and release tags run Full mode.

## Release Flow

1. Ensure `main` is green in CI.
2. Update `CHANGELOG.md`.
3. Create an annotated tag:

```powershell
git tag -a vX.Y.Z -m "vX.Y.Z: release notes"
git push origin main
git push origin vX.Y.Z
```

## Commit and PR Guidance

- Write clear, action-oriented commit messages.
- Keep PRs focused to one logical change.
- Include validation evidence in PR descriptions:
  - smoke check mode used
  - key command outputs (summary)
  - any known caveats
