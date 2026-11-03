# 14. AWS Mumbai (ap-south-1) production architecture

The target production layout in `ap-south-1`. **Almost all of it is PLANNED for step 10.1** (Terraform module set, cost model; the execution plan limits local verification to `terraform validate`). What `infrastructure/terraform` contains today was checked: one module, `modules/mail-storage` (S3 mail and archive buckets with SSE-KMS, versioning, public-access block, TLS-only bucket policy and a mail-bucket lifecycle), composed by `environments/dev` together with one customer-managed KMS key. It has never been applied.

```mermaid
flowchart TB
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  senders["Internet MTAs"]:::ext
  users["Admins, end users"]:::ext
  r53["Route 53: MX, portal, API records<br/>PLANNED 10.1"]:::planned

  subgraph region["AWS ap-south-1 Mumbai"]
    subgraph vpc["VPC across 3 AZs: aps1-az1, az2, az3<br/>PLANNED 10.1 network module"]
      subgraph pub["Public subnets"]
        nlb["NLB TCP :25<br/>PLANNED 10.1"]:::planned
        alb["ALB :443 + WAF<br/>portal and API<br/>PLANNED 10.1"]:::planned
        nat["NAT gateways, one per AZ<br/>PLANNED 10.1"]:::planned
      end
      subgraph appnet["Private app subnets"]
        pfIn["Postfix inbound ASG<br/>EBS spool, 3 AZs<br/>PLANNED 10.1 mta module"]:::planned
        pfOut["Postfix outbound ASG<br/>EBS spool, static egress IPs + PTR<br/>PLANNED 10.1 (image IMPLEMENTED 2.2)"]:::planned
        eks["EKS cluster, managed node groups, IRSA<br/>runs the Kustomize base (IMPLEMENTED manifests)<br/>PLANNED 10.1 eks module"]:::planned
        eso["External Secrets operator<br/>PLANNED 10.1"]:::planned
      end
      subgraph datanet["Private data subnets"]
        rdsW[("RDS / Aurora MySQL 8.4<br/>writer endpoint, Multi-AZ<br/>PLANNED 10.1")]:::planned
        rdsR[("Reader endpoint / read replica<br/>api control-plane reads<br/>PLANNED 10.1")]:::planned
        mq{{"Amazon MQ for RabbitMQ, 3-node cluster,<br/>or self-managed on EC2 (open decision)<br/>PLANNED 10.1"}}:::planned
        redis[("ElastiCache Redis, TLS + AUTH,<br/>Multi-AZ<br/>PLANNED 10.1")]:::planned
        os[("Amazon OpenSearch,<br/>fine-grained access control<br/>PLANNED 10.1")]:::planned
        ch[("ClickHouse Cloud or EC2<br/>PLANNED 10.1")]:::planned
      end
      vpce["VPC endpoints: S3 gateway,<br/>Secrets Manager, ECR, KMS<br/>PLANNED 10.1"]:::planned
    end
    s3[("S3 mail + archive buckets<br/>SSE-KMS, versioning, TLS-only,<br/>public access blocked<br/>IMPLEMENTED Terraform module")]:::impl
    kms["KMS customer-managed key,<br/>rotation on<br/>IMPLEMENTED environments/dev"]:::impl
    sm["Secrets Manager<br/>PLANNED 10.1 secrets module"]:::planned
    ecr["ECR images, tagged by git SHA<br/>PLANNED 10.1"]:::planned
    obs["CloudWatch, Prometheus, Grafana,<br/>tracing backend<br/>PLANNED 10.3"]:::planned
  end

  senders -.-> r53
  users -.-> r53
  r53 -.->|"MX"| nlb
  r53 -.->|"HTTPS"| alb
  nlb -.->|"TCP 25, proxy protocol"| pfIn
  alb -.-> eks
  pfIn -.->|"policy, milter, LMTP"| eks
  eks -.->|"reinject"| pfOut
  pfOut -.->|"SMTP egress"| nat
  eks -.->|"DATABASE_URL"| rdsW
  eks -.->|"DATABASE_READ_URL, api only"| rdsR
  rdsW -.->|"managed replication"| rdsR
  eks -.-> mq
  eks -.-> redis
  eks -.-> os
  eks -.-> ch
  eks -.->|"IRSA, via gateway endpoint"| vpce
  vpce -.-> s3
  kms --> s3
  sm -.-> eso
  eso -.->|"Kubernetes Secret files"| eks
  ecr -.-> eks
  eks -.-> obs
```

**Legend.** Green solid: IMPLEMENTED in `infrastructure/terraform` (validated by `terraform validate` in CI, never applied). Amber dashed: PLANNED with the step. Module names in the boxes are the planned modules from `infrastructure/terraform/README.md`.

## Design points carried into step 10.1

| Topic                       | Decision so far                                                                                                                                                                  | Source                                             |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Exposure                    | Only the MX NLB and the portal/API ALB are publicly reachable. Every data store is in private subnets and encrypted with customer-managed KMS keys                               | `infrastructure/terraform/README.md`               |
| Postfix on EC2, not EKS     | The spool must outlive pod rescheduling, so Postfix runs on ASGs with EBS spools                                                                                                 | ADR-0006                                           |
| MySQL endpoints             | `DATABASE_URL` is the writer (cluster) endpoint, `DATABASE_READ_URL` the reader endpoint. On Aurora, the lag probe needs `information_schema.replica_host_status` (PLANNED 10.1) | ADR-0014, `docs/database/replication.md`           |
| RabbitMQ                    | Amazon MQ or self-managed is an **open decision**. Quorum queues need a 3-node cluster                                                                                           | ADR-0005, Terraform README                         |
| Secrets                     | Secrets Manager → External Secrets → files read with `<KEY>_FILE`                                                                                                                | ADR-0010                                           |
| Rspamd DNS                  | A dedicated recursive resolver, because public DNSBLs refuse shared resolvers                                                                                                    | ADR-0007                                           |
| Rspamd and ClamAV placement | Not decided (EKS Deployments next to the workers, or co-located with Postfix for milter latency)                                                                                 | Open, 10.1                                         |
| `smtp-adapter` reachability | Postfix on EC2 must reach the policy port `:10040` and LMTP; the Kubernetes Service exposes only HTTP today                                                                      | `infrastructure/kubernetes/base/smtp-adapter.yaml` |
| S3 lifecycle                | The mail bucket expires objects after `mail_retention_days` (default 30), while message rows are kept 6 months. Aligning them is PLANNED 8.1                                     | `modules/mail-storage`, design D9                  |

## Status

| Element                                                              | Status       | Evidence                                                       |
| -------------------------------------------------------------------- | ------------ | -------------------------------------------------------------- |
| S3 buckets (mail, archive), SSE-KMS, versioning, TLS-only, lifecycle | IMPLEMENTED  | `modules/mail-storage/*.tf`; CI `iac` job `terraform validate` |
| KMS key with rotation (dev composition)                              | IMPLEMENTED  | `environments/dev/main.tf`                                     |
| Kubernetes manifests the cluster would run                           | IMPLEMENTED  | `infrastructure/kubernetes`; CI renders both overlays          |
| Everything else in the diagram                                       | PLANNED 10.1 | Monitoring stack 10.3                                          |
