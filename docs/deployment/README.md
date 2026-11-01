# Deployment

## Environments

| Environment                 | Where                                  | How                                                                                                                   |
| --------------------------- | -------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Local                       | Docker Compose                         | `docker-compose.yml` (see the root README)                                                                            |
| CI                          | GitHub Actions                         | `.github/workflows/ci.yml`: lint, typecheck, unit/e2e, migrations, then the full Compose stack with integration tests |
| Staging / Production (SaaS) | AWS EKS (ap-south-1), DR in ap-south-2 | `infrastructure/kubernetes/overlays/saas` + Terraform                                                                 |
| Dedicated customer          | Customer-specific AWS account or VPC   | `infrastructure/kubernetes/overlays/dedicated` + Terraform variables                                                  |

## Topology

- **EKS** runs the stateless Node services and the admin portal (`infrastructure/kubernetes/base`). Each Deployment has liveness, readiness and startup probes, an HPA, a PDB, zone spread and a hardened security context.
- **EC2 Auto Scaling Groups** run Postfix inbound and outbound, with EBS spools behind an NLB on port 25. The spool must outlive any pod.
- **Managed services** (via Terraform): RDS/Aurora MySQL 8.4, ElastiCache Redis, Amazon MQ for RabbitMQ (or self-managed), Amazon OpenSearch, S3 + KMS, and ClickHouse (Cloud or EC2).

## Release flow

1. Merge to `main` → CI green.
2. Build images once per commit, tag them with the git SHA, and push to ECR. _(Added with the infrastructure phase.)_
3. Run the migration Job (`APP=database` image, `prisma migrate deploy`) **before** rolling out services. Migrations must be backwards compatible with the previous release.
4. Roll out with `maxUnavailable: 0`. Readiness gates traffic.

## Building images

```bash
docker build -f infrastructure/docker/node-service.Dockerfile --build-arg APP=api -t email-gateway/api .
docker build -f infrastructure/docker/node-service.Dockerfile --build-arg APP=database -t email-gateway/db-migrate .
docker build -f infrastructure/docker/admin-portal.Dockerfile -t email-gateway/admin-portal .
```

One recipe builds every Nest service: `pnpm deploy` produces a pruned production bundle, and the Prisma client is generated inside it.

## Kubernetes

```bash
kubectl kustomize infrastructure/kubernetes/overlays/saas        # render
kubectl apply -k infrastructure/kubernetes/overlays/saas         # apply
```

The manifests expect a `email-gateway-secrets` Secret (managed by External Secrets) with the keys `database-url`, `rabbitmq-url` and `redis-url`, plus per-environment values for the ConfigMap.

## Terraform

See `infrastructure/terraform/README.md`. Remote state is per AWS account, and `backend.hcl` is not committed.
