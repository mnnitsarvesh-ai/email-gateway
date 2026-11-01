# Terraform

AWS infrastructure for the gateway. Primary region `ap-south-1` (Mumbai), DR `ap-south-2` (Hyderabad).

```
modules/            reusable building blocks (one concern each)
  mail-storage/     S3 buckets for EML/attachments and archive (implemented)
environments/
  dev/              composition for the dev account (remote state configured per account)
```

Planned modules, added in the infrastructure phase:

| Module       | Backs                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| `network`    | VPC, private subnets across 3 AZs, NAT, VPC endpoints (S3, Secrets Manager) |
| `eks`        | EKS cluster, managed node groups, IRSA, add-ons                             |
| `mysql`      | RDS/Aurora MySQL 8.4 writer + read replicas (ADR-0004)                      |
| `rabbitmq`   | Amazon MQ for RabbitMQ or self-managed (open decision)                      |
| `redis`      | ElastiCache for Redis, TLS + AUTH                                           |
| `opensearch` | Amazon OpenSearch Service, fine-grained access control                      |
| `clickhouse` | ClickHouse Cloud or self-managed on EC2                                     |
| `mta`        | Postfix EC2 Auto Scaling Groups with EBS spool, NLB on :25                  |
| `secrets`    | Secrets Manager entries consumed by External Secrets                        |

Conventions: every module takes `tags` and `environment`; all data stores are encrypted with
customer-managed KMS keys; nothing is publicly reachable except the MX NLB and the portal ALB.

```bash
cd environments/dev
terraform init -backend-config=backend.hcl   # backend.hcl is per account, not committed
terraform plan
```
