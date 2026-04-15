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
