# Changelog

## Unreleased

### Scenario Analysis Additions

- Scenario analysis CI workflow for timeline and ATT&CK heatmap validation.
- Comprehensive operator guide for scenario analysis tooling and workflows.
- Stakeholder-facing milestone release notes for the 2026-04-15 scenario analysis delivery.
- Reusable monthly release-notes template for future scenario analysis milestones.

### Scenario Analysis Changes

- Standardized 10 scenario reports to the common analysis template with Overview, Input Evidence Bundle, Key Detection Signals, Expected Classification, SOC Actions, Timeline, and Analyst Guidance sections.
- Linked release-note workflow artifacts from README and CONTRIBUTING for easier discoverability.

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
