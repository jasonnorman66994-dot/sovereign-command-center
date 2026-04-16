# AWS Infrastructure Patterns: Networking, Lambda, and EC2

Version: 1.0  
Last Updated: 2026-04-16

---

## Purpose

Provide practical AWS infrastructure patterns that align with enterprise network, serverless, and compute workloads.

---

## VPC Networking Patterns

### Pattern A: Single-VPC Tiered Application

- Public subnets for ALB and NAT Gateway
- Private app subnets for ECS/EC2/Lambda ENIs
- Private data subnets for RDS/ElastiCache

Use when:

- One business domain
- Moderate compliance requirements

### Pattern B: Multi-VPC Shared Services

- Shared services VPC (inspection, transit, DNS)
- Application VPC per product/team
- Centralized routing via Transit Gateway

Use when:

- Multi-team scale
- Centralized governance

### Pattern C: Multi-Region VPC DR

- Active-passive regional architecture
- Route 53 health checks and failover routing
- Cross-region database replication

Use when:

- Strict resilience and continuity targets

---

## Lambda Architecture Patterns

### Pattern 1: API-Driven Lambda

Components:

- API Gateway
- Lambda
- DynamoDB or Aurora Serverless
- CloudWatch and X-Ray

Best for:

- Bursty HTTP workloads
- Event-driven APIs

### Pattern 2: Event Ingestion Lambda

Components:

- EventBridge or SQS
- Lambda consumer
- DLQ for poison messages

Best for:

- Asynchronous workflows
- Integration/event normalization

### Pattern 3: VPC-Integrated Lambda

Components:

- Lambda in private subnet
- NAT Gateway for egress
- SG rules for database/internal APIs

Best for:

- Private data access
- Controlled egress and compliance

---

## EC2 Architecture Patterns

### Pattern 1: Auto Scaling Web Tier

- ALB in public subnets
- EC2 ASG in private app subnets
- Launch template with hardened AMI

### Pattern 2: Stateful EC2 Service

- EC2 in private subnets
- EBS optimized storage
- Backup and patch windows

### Pattern 3: Bastionless Operations

- SSM Session Manager
- No inbound SSH/RDP
- IAM and logging enforced

---

## Security Baselines

- Use SG-first filtering, NACL for subnet-level constraints.
- No 0.0.0.0/0 admin ingress.
- Encrypt EBS, RDS, S3 with KMS.
- Enable GuardDuty, Security Hub, CloudTrail organization trails.

---

## Cost Optimization Notes

- Prefer Graviton instance families where compatible.
- Use Savings Plans for steady-state EC2.
- Use Lambda power tuning for cost/performance balance.
- Use NAT Gateway per AZ only where required; optimize egress architecture.

---

## Mapping to Azure Equivalents

| AWS | Azure Equivalent |
|---|---|
| VPC | Virtual Network |
| Security Group | NSG |
| Transit Gateway | Virtual WAN / Hub routing |
| Route 53 Failover | Traffic Manager / Front Door |
| Lambda | Azure Functions |
| ALB | Application Gateway |
| NLB | Load Balancer |
| IAM Role | Managed Identity + RBAC |
