# ADR-0012: Shared-schema multi-tenancy; SaaS and dedicated deployments differ only by config

**Status:** Accepted

**Decision.**

- **Shared schema with a tenant column.** Every tenant-owned table has a non-null `tenant_id`, its indexes lead with it, and every repository query filters by it. The tenant comes from the authenticated principal, the mail connector or verified domain, or the event envelope. **It never comes from request headers.**
- Domains are globally unique (`tenant_domains.domain UNIQUE`), so a domain can't be claimed by two tenants.
- **Deployment modes** are configuration: the Kustomize overlays `saas` and `dedicated`, Terraform variables and `DEPLOYMENT_MODE`. Code must not branch on deployment mode or on specific tenant ids. Differences go into config or tenant policy.

**Alternatives.** Schema- or database-per-tenant gives stronger isolation but is operationally heavy at many-tenant SaaS scale. Customers who need that isolation get a dedicated deployment.

**Consequences.** Tenant-aware authorization becomes a guard plus repository-layer enforcement, delivered with the Identity phase and covered by cross-tenant access tests.
