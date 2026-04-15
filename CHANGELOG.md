# Changelog

## v1.0.0 - 2026-04-15

### Added

- Initial repository baseline import for sovereign-command-center.
- Automated validation workflow via smoke_check.ps1 with Quick and Full modes.
- Markdown linting configuration and scoped lint profiles.
- Python syntax validation in smoke checks.
- Repository Git hook automation:
  - pre-commit runs Quick smoke check.
  - pre-push runs Full smoke check.
- Scenario and timeline documentation normalization for SOC drill content.

### Infrastructure

- GitHub remote tracking configured for main.
- Initial release baseline published from commit 9d17e65.
