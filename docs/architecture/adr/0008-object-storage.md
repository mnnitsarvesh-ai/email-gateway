# ADR-0008: S3 for message content; MinIO for local development

**Status:** Accepted

**Decision.**

- AWS S3 holds EML, extracted attachments and archive copies. SSE-KMS, versioning, TLS-only bucket policies and blocked public access (`infrastructure/terraform/modules/mail-storage`).
- **Tenant-first keys**: `org/{tenantId}/eml/{yyyy}/{mm}/{dd}/{messageId}.eml`, `org/{tenantId}/part/...`, `org/{tenantId}/archive/...`. Per-tenant export or deletion is a prefix operation, and workers verify that the key prefix matches the event's tenant.
- Queues and DB rows carry keys, never bodies. Ingestion streams to S3 and never buffers whole messages in memory.
- **Local**: MinIO through the same AWS SDK (`S3_ENDPOINT`, path-style). Upstream MinIO no longer publishes container images, so Compose uses Chainguard's `minio` image **pinned by digest**. Its `-dev` variant includes `mc` and `wget` for the bucket bootstrap and the health check.

**Consequences.** Swapping MinIO for another S3-compatible store (or LocalStack) is a Compose-only change. Review the MinIO image digest whenever it is updated.
