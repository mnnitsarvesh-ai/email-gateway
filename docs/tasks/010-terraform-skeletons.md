# 010: Terraform module skeletons and env roots (saas/dedicated × ap-south-1/ap-south-2)

Owner agent: devops-engineer
Depends on: 001
Status: draft
Branch: feat/010-terraform-skeletons
Phase: 0

## User story

Story: _to be written by product-owner_

As a platform operator, I want the Terraform layout, module interfaces and CI checks in place from day one so that infrastructure grows module by module under fmt/validate/test gates and SaaS and dedicated differ only by variables.

## Acceptance criteria

AC-1 Given `infra/terraform/`, when listed, then it has modules `vpc, eks, postfix-asg, mysql, rabbitmq, s3, opensearch, clickhouse, redis` (each with `versions.tf variables.tf outputs.tf main.tf README.md tests/plan.tftest.hcl`) and env roots `saas/primary, saas/dr, dedicated/primary, dedicated/dr`.
AC-2 Given `terraform fmt -check -recursive infra/terraform`, when run, then it exits 0; after introducing a badly formatted file it exits non-zero.
AC-3 Given each module and env root, when `terraform init -backend=false && terraform validate` runs, then it exits 0 with no credentials set.
AC-4 Given each module, when `terraform test` runs, then every run passes using `mock_provider "aws"`; `required_version >= 1.7` and the aws provider is pinned to 6.x with the lock file committed.
AC-5 Given the `s3` module, when planned in test, then the mail and archive buckets have public access blocked, a TLS-only bucket policy, SSE-KMS with bucket keys and versioning; Object Lock on archive is off by default.
AC-6 Given the `postfix-asg` module, when planned in test, then the spool EBS volume is encrypted gp3, a scale-in lifecycle hook exists, and the inbound NLB listens on TCP 25 with client-IP preservation.
AC-7 Given the `mysql` module outputs, when planned, then `writer_secret_arn` differs from `reader_secret_arn`, and no output exposes a password value; no `random_password` output exists (grep).
AC-8 Given `mysql` and `rabbitmq` modules, when planned, then they are interface-only (no resources beyond placeholders) and `engine_choice` rejects unknown values via a validation block (blocked by ADR-025/ADR-024).
AC-9 Given the env roots, when compared (`diff` of module calls), then SaaS and dedicated call the same modules and differ only in tfvars; `grep -rn 'deployment_mode ==' infra/terraform/modules` returns nothing.
AC-10 Given a `region` variable set to `us-east-1`, when validated, then `terraform validate`/`test` fails; `ap-south-1` and `ap-south-2` pass.
AC-11 Given `default_tags`, when planned, then `project=esg`, `env`, `deployment_mode`, `region_role` and `managed_by=terraform` are present on resources.
AC-12 Given `backend.tf`, when read, then it declares only `backend "s3" {}`; `backend.hcl.example` has placeholders; `backend.hcl` and `*.tfvars` (other than `*.example`) are gitignored.
AC-13 Given the CI `terraform` job, when it runs, then it executes fmt, validate, `terraform test`, `tflint` (with `.tflint.hcl`) and a config scanner (`trivy config` or `checkov`) with a committed baseline, and a deliberately insecure fixture (public bucket) makes the scanner fail.
AC-14 Given the workflow files and scripts, when searched, then no `terraform apply`, `destroy`, `aws` CLI call or cloud credential appears; every `init` uses `-backend=false`.
AC-15 Given gitleaks over `infra/`, when run, then it exits 0 and no state file or secret is tracked.

### Open questions for Sarvesh

- NEEDS SARVESH #1 to #3 (ClickHouse hosting, Valkey versus Redis, dedicated account topology) are not tested; AC-1 only requires the `clickhouse` and `redis` interfaces with placeholder variables. If Valkey is accepted, the `redis` `engine` validation values change.

## Out of scope

- **Any `terraform apply` or `destroy`, any `plan` against a real backend or with real credentials, and the `aws` CLI** (hard rule 10). Sarvesh runs every apply.
- Real resource implementations for `mysql` and `rabbitmq`. They are blocked by **ADR-025** and **ADR-024**, so only their interfaces exist here.
- Helm charts, ArgoCD and the EKS add-ons (Phase 1–2 infra track).
- Remote-state bootstrap (state bucket and lock). That's a human task.

## Design notes

### Layout

```
infra/terraform/
  modules/
    vpc/  eks/  postfix-asg/  mysql/  rabbitmq/  s3/  opensearch/  clickhouse/  redis/
      each: versions.tf  variables.tf  outputs.tf  main.tf  README.md  tests/plan.tftest.hcl
  envs/
    saas/primary/      (ap-south-1)     main.tf  variables.tf  backend.tf  saas-primary.tfvars.example
    saas/dr/           (ap-south-2)
    dedicated/primary/ (ap-south-1)     dedicated.tfvars.example   # one tfvars per customer: dedicated-<name>.tfvars (Sarvesh-owned, not committed if it contains anything sensitive)
    dedicated/dr/      (ap-south-2)
  .tflint.hcl
```

### Versions and backend

- `required_version` is pinned to a Terraform release of at least 1.7, which is needed for `mock_provider` in `terraform test`. The `hashicorp/aws` provider is pinned to the 6.x series, or the current major at implementation time, with the lock file committed.
- `backend.tf` declares only `backend "s3" {}` (partial config). The real values go in `backend.hcl`, which Sarvesh provides and which is not committed. A `backend.hcl.example` holds placeholders.
- Agents and CI always run `terraform init -backend=false`.

### Same modules, different vars (ADR-018)

- SaaS and dedicated env roots call **the same modules**. Differences live only in tfvars: sizes, counts, `deployment_mode` (used only for tags and naming), CIDRs and the DR toggle.
- No `count = var.deployment_mode == "dedicated" ? …` inside modules. Modules expose capacity and feature variables, and the env roots set them.

### Provider and tags

`default_tags` cover `project=esg`, `env`, `deployment_mode`, `region_role` (`primary` or `dr`) and `managed_by=terraform`. The region is a variable, validated to `ap-south-1` or `ap-south-2`.

### Module interfaces

These are the skeleton deliverables. Each output is typed and documented.

| Module | Key inputs | Key outputs | Skeleton depth |
|---|---|---|---|
| `vpc` | `cidr`, `az_count` (3), `enable_nat` | `vpc_id`, `private_subnet_ids`, `public_subnet_ids`, `data_subnet_ids` | Real resources |
| `eks` | `cluster_version`, `node_groups`, `subnet_ids` | `cluster_name`, `oidc_provider_arn` | Interface plus a minimal cluster resource |
| `postfix-asg` | `role` (`inbound`\|`outbound`), `instance_type`, `min/max/desired`, `spool_volume_gb`, `subnet_ids`, `eip_allocation_ids` (outbound) | `asg_name`, `nlb_dns_name` (inbound), `egress_ips` (outbound) | Launch template, encrypted gp3 EBS spool, **scale-in lifecycle hook for queue drain**, an inbound NLB on TCP 25 with client-IP preservation, so `policy-adapter` and SPF see the real sender IP |
| `mysql` | `engine_choice` (validated placeholder; **blocked by ADR-025**), `instance_class`, `replica_count`, `dr_replica` | `writer_endpoint`, `reader_endpoint`, **`writer_secret_arn`, `reader_secret_arn` (separate, so data-plane pods only get the writer secret)** | Interface only |
| `rabbitmq` | `engine_choice` (**blocked by ADR-024**), `node_count` (3) | `amqps_endpoints`, `secret_arn` | Interface only |
| `s3` | `buckets` (mail, archive), `kms_key_arn`, `lifecycle_rules`, `object_lock` (archive, off by default) | bucket names and ARNs | Real resources: block public access, TLS-only bucket policy, SSE-KMS with bucket keys, versioning |
| `opensearch` | `instance_type`, `instance_count`, `zone_awareness` | `endpoint` | Interface plus a minimal domain resource |
| `clickhouse` | `hosting` (placeholder, see NEEDS SARVESH) | `endpoint`, `secret_arn` | Interface only |
| `redis` | `engine` (`redis`\|`valkey`, see NEEDS SARVESH), `node_type`, `replicas` | `primary_endpoint`, `secret_arn` | Interface plus an ElastiCache replication group |

### No secrets in state where avoidable

- Use `manage_master_user_password = true` (RDS) or the equivalent, so passwords are kept in Secrets Manager and not in state.
- No `random_password` outputs. Modules output secret ARNs, never values.

### CI (extends the job stub from 001)

- `terraform fmt -check -recursive`.
- For every module and env root: `init -backend=false` then `validate`.
- `terraform test` in every module. It uses `mock_provider "aws"` and makes plan-level assertions, for example:
  - S3 blocks public access;
  - the EBS spool is encrypted;
  - the NLB listens on 25;
  - the lifecycle hook exists;
  - `writer_secret_arn != reader_secret_arn`.
- `tflint`, plus a config scanner (`trivy config` or `checkov`) with a committed baseline.

### Plan

`terraform plan` runs only against env roots with mock providers, through `terraform test` `command = plan` runs. **Never** against real AWS.

## Hard rules at risk

- **10 (no apply or cloud access).** Use `-backend=false`, mock providers, and keep cloud credentials out of CI.
- **9 (no secrets).** Partial backend config is not committed. Secrets are managed by AWS and outputs are ARNs only. `*.tfvars` is gitignored except `*.example`.
- **2 (writer-only data plane).** Separate writer and reader secret outputs, so Helm can give data-plane pods only the writer.
- **ADR-018.** One module set, with differences only in tfvars.
- **ADR-001 and ADR-022 (Postfix spool durability).** The skeleton includes the encrypted EBS spool and the drain lifecycle hook.

## NEEDS SARVESH

1. **ClickHouse hosting** (vendor and cost). Options:
   - (a) ClickHouse Cloud on AWS ap-south-1 (managed; check that it's offered in Mumbai, its DR story, and that data stays in India);
   - (b) self-managed on EKS with the Altinity operator;
   - (c) self-managed on EC2.

   *Recommendation:* (a) if it's available in ap-south-1 and the DPA covers DPDP. Otherwise (b).
2. **ElastiCache engine: Redis OSS vs Valkey.** ADR-009 says Redis. Valkey is protocol-compatible and cheaper on ElastiCache. *Recommendation:* Valkey (keeping the `redis` client), recorded as a new ADR if accepted.
3. **AWS account topology for dedicated deployments.** Options: (a) dedicated tenants in separate accounts in our AWS Organization; (b) in the customer's own AWS account (we deploy, they own it). *Recommendation:* (a) by default, with (b) offered as an option. The decision changes the state and backend layout and the IAM model.
4. **ADR-024 and ADR-025.** The `rabbitmq` and `mysql` modules stay as interfaces until these are decided. They need a decision by the end of week 10 (see the roadmap).
