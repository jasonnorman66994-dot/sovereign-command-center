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

### Azure Infrastructure Additions

- Azure Networking Resources Cheat Sheet: Quick reference guide for VNets, NSGs, firewalls, load balancers, gateways, and hub-spoke deployment patterns.
- Azure Networking Decision Matrix: Scenario-based decision matrix for selecting the right Azure networking resource across load balancing, security, hybrid connectivity, DNS, and specialized networking.
- Azure Architecture Comparison (Cloud-Native vs Hybrid vs Multi-Region): Detailed analysis with strengths, limitations, best-fit scenarios, decision tree, and implementation roadmap for three common Azure architectures.
- Added Azure Infrastructure & Architecture References section to README for improved discoverability of all three reference documents.

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
