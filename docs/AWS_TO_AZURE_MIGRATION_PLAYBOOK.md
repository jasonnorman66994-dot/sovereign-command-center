# AWS to Azure Migration Playbook

Version: 1.0  
Last Updated: 2026-04-16

---

## Objective

Guide migration planning and execution from AWS workloads to Azure, with focus on networking, Lambda modernization, and EC2 platform migration.

---

## Migration Phases

1. Discovery and inventory
2. Dependency mapping
3. Target architecture definition
4. Pilot migration
5. Wave-based execution
6. Cutover and optimization

---

## Workload Mapping

| AWS Service | Azure Target | Notes |
|---|---|---|
| VPC | Virtual Network | Preserve CIDR strategy and segmentation |
| Transit Gateway | Hub-spoke / Virtual WAN | Centralized routing and inspection |
| Security Groups | NSG | Translate stateful allow rules carefully |
| NACL | Route and NSG policy overlays | Keep subnet-level controls minimal |
| Route 53 | Azure DNS + Traffic Manager | Global failover patterns |
| Lambda | Azure Functions | Rework triggers and runtime packaging |
| API Gateway | API Management / Functions HTTP | Policy and auth parity required |
| EC2 | Azure VM/VMSS | Rebuild via image or app-level redeploy |
| CloudWatch | Azure Monitor + Log Analytics | Migrate alerts and dashboards |

---

## Networking Migration Steps

1. Build Azure hub-spoke baseline.
2. Establish hybrid AWS-Azure connectivity for transition.
3. Migrate shared services DNS and identity dependencies.
4. Move application spokes in waves.
5. Decommission AWS routing dependencies after validation.

---

## Lambda to Functions Migration Checklist

- Confirm trigger type mapping (API, queue, event bus, schedule).
- Validate runtime compatibility and package dependencies.
- Replace IAM assumptions with managed identity and RBAC.
- Update observability to Application Insights/Azure Monitor.
- Test cold start and concurrency behavior.

---

## EC2 to Azure VM Migration Checklist

- Right-size VM families and disks.
- Rebuild infrastructure as code in Bicep/Terraform.
- Use Azure Backup and update patch policies.
- Migrate security controls to NSG + Firewall model.

---

## Cutover Plan

1. Run dual-write/readiness tests where applicable.
2. Freeze high-risk schema or config changes.
3. Shift traffic gradually using weighted routing.
4. Validate KPIs and business workflows.
5. Finalize DNS and endpoint cutover.

Rollback:

- Maintain reversible DNS/traffic routing for defined window.
- Keep source environment warm until stability criteria met.

---

## Governance and Security

- Use Azure Policy for baseline enforcement.
- Require private endpoints for sensitive data paths.
- Enforce least privilege via RBAC and managed identities.
- Log all control-plane changes and monitor anomalies.

---

## Success Metrics

- Migration wave success rate
- P1/P2 incident count post-cutover
- Cost delta versus AWS baseline
- Performance SLO attainment
- Security finding reduction trend

---

## Tooling Notes

- Prefer IaC-first migration execution.
- Keep migration runbooks versioned with the application code.
- Use non-production rehearsals before each wave.
