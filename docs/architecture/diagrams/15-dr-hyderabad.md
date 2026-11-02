# 15. Hyderabad (ap-south-2) disaster recovery architecture

A warm standby in `ap-south-2` for a regional loss of `ap-south-1`. **Everything here is PLANNED for step 10.2** (warm standby IaC, runbooks, reconciliation). The execution plan states that this step is **design only from this workstation**, and that RPO and RTO cannot be claimed without a real regional test. The numbers below are targets, **not verified**.

```mermaid
flowchart LR
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  senders["Internet MTAs<br/>queue and retry for days on 4xx<br/>or when no MX answers"]:::ext
  r53["Route 53<br/>health checks + failover records for MX,<br/>portal and API<br/>PLANNED 10.2"]:::planned

  subgraph primary["ap-south-1 Mumbai: active"]
    pNlb["NLB :25 + Postfix ASG"]:::planned
    pEks["EKS: all services"]:::planned
    pRds[("RDS / Aurora writer")]:::planned
    pS3[("S3 mail + archive")]:::planned
    pMq{{"RabbitMQ"}}:::planned
  end

  subgraph dr["ap-south-2 Hyderabad: warm standby"]
    dNlb["NLB :25 + Postfix ASG<br/>minimum capacity"]:::planned
    dEks["EKS: services scaled to minimum,<br/>same images and overlay"]:::planned
    dRds[("Cross-region read replica,<br/>promoted on failover,<br/>or restore from copied snapshot")]:::planned
    dS3[("S3 replica buckets<br/>replica KMS key")]:::planned
    dMq{{"RabbitMQ, empty at failover"}}:::planned
    dRedis[("Redis, cold cache")]:::planned
    recon["Reconciliation job:<br/>rebuild in-flight work from MySQL<br/>status + unpublished outbox<br/>PLANNED 10.2"]:::planned
  end

  senders -.-> r53
  r53 -.->|"primary"| pNlb
  r53 -.->|"failover"| dNlb
  pNlb -.-> pEks
  pEks -.-> pRds
  pEks -.-> pS3
  pEks -.-> pMq
  pRds -.->|"async cross-region replication<br/>or daily snapshot copy"| dRds
  pS3 -.->|"S3 Cross-Region Replication"| dS3
  dNlb -.-> dEks
  dEks -.-> dRds
  dEks -.-> dS3
  dEks -.-> dMq
  dEks -.-> dRedis
  recon -.->|"re-publish"| dMq
  recon -.->|"reads"| dRds
```

**Legend.** Every element is PLANNED (step 10.2; the primary-region boxes are PLANNED 10.1). Nothing in this diagram exists in the repository today.

## What is replicated and how

| Data                   | Mechanism                                                                                                                       | Notes                                                                                                                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| MySQL                  | Cross-region read replica (RDS) or Aurora Global Database, promoted on failover. Fallback: daily snapshots copied to ap-south-2 | Design D9 (`docs/database/backup-restore.md`, WP4) records snapshot copies and PITR. The choice between a live replica and snapshot copy sets the RPO                                      |
| S3 (EML, archive)      | Cross-Region Replication with versioning (already on in the module) and a replica KMS key                                       | Object keys outlive rows, so a replica that is ahead of MySQL is safe                                                                                                                      |
| RabbitMQ               | Not replicated across regions                                                                                                   | In-flight work is rebuilt by reconciliation: messages in non-terminal states (query Q7) and outbox rows with `published_at IS NULL` are re-published. `processOnce` makes the replays safe |
| Redis                  | Not replicated                                                                                                                  | Caches and rate-limit counters only; never the source of truth                                                                                                                             |
| OpenSearch, ClickHouse | Snapshot restore or rebuild from MySQL and S3                                                                                   | Not on the mail path; reporting may lag after a failover                                                                                                                                   |
| Postfix spools         | Not replicated                                                                                                                  | Mail in a lost primary spool that was not yet ingested is the main mail-loss risk; senders' own queues cover mail that never got a `250`                                                   |

## MX failover options (decision for step 10.2)

| Option                                  | Behaviour                                                                                                                                                              |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Route 53 failover record on the MX host | Health check on the primary NLB; on failure the MX name resolves to the DR NLB. DNS TTL bounds the switch time                                                         |
| Secondary MX at a lower priority        | Senders fall back by themselves. The DR Postfix must then apply the **same** in-session checks (policy delegation and milter) to avoid becoming a weaker path for spam |

## Targets (unverified)

| Objective                        | Target                                                                          | Depends on                               |
| -------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------- |
| RPO, MySQL                       | Minutes with a cross-region replica. Up to 24 h with daily snapshot copies only | The replication mechanism chosen in 10.2 |
| RPO, mail not yet answered `250` | Zero: the sender keeps it and retries                                           | Fail-closed edge (ADR-0006)              |
| RTO, mail acceptance             | Target to be set in 10.2 (warm standby, scale-up time plus DNS TTL)             | Pre-provisioned DR capacity              |

These targets are design intent. They become claims only after the regional failover test in step 10.2.
