# ADR-0009: OpenSearch for search, ClickHouse for analytics

**Status:** Accepted

**Decision.**

- **OpenSearch** indexes message-trace metadata (sender, recipients, subject hash or subject, verdicts, actions, timestamps) for portal search. Tenant isolation uses a mandatory `tenantId` filter in the query layer, with index-per-time-window and aliases for retention.
- **ClickHouse** stores the event history (every pipeline event) for dashboards, reports and trend analysis. MySQL is not used for analytics.
- Both are fed asynchronously from RabbitMQ events and are **not** on the critical mail path: if they are down, mail still flows and indexing catches up.
- Local development runs both under the Compose `analytics` profile. The OpenSearch security plugin is disabled locally only.

**Consequences.** Search and analytics are eventually consistent (seconds). Each store has its own retention policy per tenant plan.
