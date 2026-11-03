# 4. SaaS deployment

The shared multi-tenant deployment: one EKS cluster per environment rendered from `infrastructure/kubernetes/overlays/saas`, Postfix on EC2 Auto Scaling Groups, and managed AWS data stores. The Kubernetes manifests exist and render in CI. The cluster, the Postfix ASGs and every managed service except S3 are PLANNED for step 10.1.

```mermaid
flowchart TB
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  internet["Internet senders, admins"]:::ext
  nlb["NLB :25<br/>PLANNED 10.1"]:::planned
  alb["ALB :443 portal + API<br/>PLANNED 10.1"]:::planned

  subgraph ec2["EC2 Auto Scaling Groups, EBS spool"]
    pfIn["Postfix inbound<br/>PLANNED 10.1, image local only"]:::planned
    pfOut["Postfix outbound<br/>PLANNED 10.1, image local only<br/>(model: docs/deployment/smtp-gateway.md)"]:::planned
  end

  subgraph eks["EKS namespace email-gateway, Pod Security restricted"]
    overlay["overlays/saas<br/>APP_ENV=production, DEPLOYMENT_MODE=saas"]:::impl
    deps["8 Deployments + Service + HPA + PDB<br/>api 2-6, smtp-adapter 2-6, email-worker 3-30,<br/>policy-engine 2-10, delivery-worker 2-10,<br/>notification 1-4, archive 1-6, admin-portal 2-6"]:::impl
    cfg["ConfigMap email-gateway-config"]:::impl
    sec["Secret email-gateway-secrets<br/>mounted at /var/run/secrets/gateway"]:::impl
    eso["External Secrets operator<br/>PLANNED 10.1"]:::planned
    migrate["db-migrate Job<br/>PLANNED, not in base yet"]:::planned
    maint["db-maintenance CronJob<br/>partition maintenance, 01:30 UTC"]:::impl
    engines["Rspamd, ClamAV<br/>placement PLANNED 10.1"]:::planned
  end

  subgraph managed["Managed services"]
    rds[("RDS / Aurora MySQL 8.4<br/>writer + reader endpoints<br/>PLANNED 10.1")]:::planned
    mq{{"Amazon MQ RabbitMQ<br/>or self-managed<br/>PLANNED 10.1"}}:::planned
    cache[("ElastiCache Redis<br/>PLANNED 10.1")]:::planned
    s3[("S3 mail + archive, SSE-KMS<br/>Terraform module IMPLEMENTED")]:::impl
    sm["Secrets Manager<br/>PLANNED 10.1"]:::planned
    search[("OpenSearch, ClickHouse<br/>PLANNED 10.1")]:::planned
  end

  internet -.-> nlb
  internet -.-> alb
  nlb -.->|"P 10.1"| pfIn
  alb -.->|"P 10.1"| deps
  pfIn -.->|"policy, socketmap, SASL, LMTP<br/>needs internal ports, P 10.1"| deps
  deps -.->|"SMTP reinject, P 2.3"| pfOut
  overlay --> deps
  cfg --> deps
  sec --> deps
  sm -.->|"synced by"| eso
  eso -.->|"writes"| sec
  deps -.->|"DATABASE_URL_FILE writer,<br/>DATABASE_READ_URL_FILE api only"| rds
  deps -.-> mq
  deps -.-> cache
  deps -.-> s3
  deps -.-> search
  migrate -.->|"MIGRATION_DATABASE_URL"| rds
  maint -.->|"DDL account"| rds
```

**Legend.** Green solid: IMPLEMENTED (manifests that render with `kubectl kustomize` in CI, and the Terraform S3 module that passes `terraform validate`). Amber dashed: PLANNED.

## Status

| Element                                           | Status       | Evidence or delivering step                                                                                                                                                                                                                                                 |
| ------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kustomize base: 8 Deployments, Services, HPA, PDB | IMPLEMENTED  | `infrastructure/kubernetes/base/*.yaml`; rendered by the CI `iac` job. Probes `/health/live` and `/health/ready`, zone spread, read-only root filesystem                                                                                                                    |
| `overlays/saas`                                   | IMPLEMENTED  | `infrastructure/kubernetes/overlays/saas/kustomization.yaml`                                                                                                                                                                                                                |
| Secret mount and `<KEY>_FILE` convention          | IMPLEMENTED  | `packages/config` (`load-config.test.ts`); manifests read `DATABASE_URL_FILE`, `DATABASE_READ_URL_FILE` (api only), `RABBITMQ_URL_FILE`, `REDIS_URL_FILE`                                                                                                                   |
| S3 buckets with SSE-KMS, versioning, TLS-only     | IMPLEMENTED  | `infrastructure/terraform/modules/mail-storage`; `terraform validate` in CI. Never applied                                                                                                                                                                                  |
| EKS cluster, NLB, ALB, Postfix ASGs               | PLANNED 10.1 | `infrastructure/terraform/README.md` lists the planned modules                                                                                                                                                                                                              |
| RDS/Aurora, Amazon MQ, ElastiCache, OpenSearch    | PLANNED 10.1 |                                                                                                                                                                                                                                                                             |
| External Secrets operator and Secrets Manager     | PLANNED 10.1 | ADR-0010                                                                                                                                                                                                                                                                    |
| Migration Job                                     | PLANNED      | `docs/deployment/README.md`: "not in base yet"                                                                                                                                                                                                                              |
| Partition maintenance CronJob                     | IMPLEMENTED  | `infrastructure/kubernetes/base/db-maintenance.yaml`, rendered by the CI Kustomize step; the job logic is covered by `partitions.test.ts` and the partitioning unit tests. Never applied to a cluster                                                                       |
| smtp-adapter mail ports on the Service            | PLANNED 10.1 | The `smtp-adapter` Service exposes only `http` (port 80 → 3010). Postfix on EC2 needs `:10040`–`:10042` and `:10050`–`:10052` through an internal NLB; Kubernetes manifests were out of scope in step 2.2 (design D18, [smtp-gateway.md](../../deployment/smtp-gateway.md)) |
| Rspamd and ClamAV placement in AWS                | PLANNED 10.1 | Not in the Kustomize base                                                                                                                                                                                                                                                   |
