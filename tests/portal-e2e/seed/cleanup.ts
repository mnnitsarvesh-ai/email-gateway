/**
 * Removes every row and object of the previous run (organizations whose slug starts with
 * `e2e-portal-`, and the platform users of the run, `@e2e-portal.test`). Follows the cleanup
 * order of the api integration helpers (apps/api/integration/support: the quarantine purge order
 * of QuarantineTenantDataRepository, then the message graph of lifecycle.ts / messages-data.ts,
 * then Fixtures.cleanup); partitioned tables are deleted with a predicate on their partition
 * column as well (pruning), S3 objects by key under `org/<organizationId>/`. `audit_logs` stays
 * (append-only by policy, as in the integration suites). Table names come from the fixed lists
 * below, never from input.
 */
import { DeleteObjectsCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { PLATFORM_ORGANIZATION_SLUG, Prisma, type PrismaClient } from '@email-gateway/database';
import { mailBucket } from './db';

export const ORG_SLUG_PREFIX = 'e2e-portal-';
export const PLATFORM_EMAIL_SUFFIX = '@e2e-portal.test';

/** Partitioned tables and their partition column (docs/database/partitioning.md). */
const PARTITION_COLUMN: Record<string, string> = {
  attachment_scan_results: 'received_at',
  bec_scan_results: 'received_at',
  bounce_events: 'occurred_at',
  delivery_attempts: 'received_at',
  delivery_reinjections: 'received_at',
  delivery_status_events: 'received_at',
  dlp_evidence: 'received_at',
  dlp_scan_results: 'received_at',
  email_archives: 'received_at',
  email_attachments: 'received_at',
  email_auth_results: 'received_at',
  email_deliveries: 'received_at',
  email_events: 'received_at',
  email_headers: 'received_at',
  email_message_parses: 'received_at',
  email_message_status_history: 'received_at',
  email_messages: 'received_at',
  email_recipients: 'received_at',
  email_scans: 'received_at',
  message_outbox: 'created_at',
  message_risk_scores: 'received_at',
  message_urls: 'received_at',
  policy_execution_logs: 'received_at',
  sandbox_submissions: 'received_at',
  scan_engine_results: 'received_at',
  url_click_events: 'clicked_at',
  url_dynamic_inspections: 'received_at',
  url_rewrites: 'received_at',
  url_scan_results: 'received_at',
  webhook_deliveries: 'event_occurred_at',
  webhook_delivery_attempts: 'attempted_at',
  webhook_events: 'occurred_at',
};

/** Delete order (every table with `organization_id` except `audit_logs` and `organizations`). */
const ORDER = [
  // Quarantine purge order (step 5.3 Q17).
  'quarantine_download_grants',
  'quarantine_approval_requests',
  'quarantine_release_logs',
  'quarantine_actions',
  'quarantine_object_purges',
  'quarantine_digests',
  'quarantine_digest_runs',
  'quarantine_user_preferences',
  'quarantine_messages',
  'quarantine_settings',
  // Message graph (quarantine.ts deleteQuarantineFixtures, messages-data.ts, lifecycle.ts).
  'message_outbox',
  'archive_legal_holds',
  'archive_retention_policies',
  'archive_settings',
  'email_archives',
  'message_risk_scores',
  'email_auth_results',
  'scan_engine_results',
  'attachment_scan_results',
  'url_click_events',
  'url_rewrites',
  'url_dynamic_inspections',
  'url_scan_results',
  'message_urls',
  'email_attachments',
  'email_headers',
  'policy_execution_logs',
  'bec_scan_results',
  'dlp_scan_results',
  'dlp_evidence',
  'sandbox_submissions',
  'sandbox_analyses',
  'email_scans',
  'email_message_status_history',
  'email_events',
  'api_idempotency_keys',
  'email_message_parses',
  'delivery_status_events',
  'delivery_attempts',
  'delivery_reinjections',
  'bounce_events',
  'email_deliveries',
  'email_recipients',
  'email_messages',
  'message_identities',
  'delivery_suppressions',
  'delivery_routes',
  // Fixtures.cleanup order (auth, connectors, domains, roles, users, organization rows).
  'login_audit_logs',
  'user_tokens',
  'user_mfa_recovery_codes',
  'user_sessions',
  'api_keys',
  'smtp_connector_networks',
  'smtp_connectors',
  'domain_recipient_addresses',
  'domain_mail_servers',
  'domain_mx_records',
  'domain_dkim_keys',
  'domain_dns_records',
  'domain_verifications',
  'domain_settings',
  'domains',
  'tenant_department_members',
  'tenant_departments',
  'notification_user_preferences',
  'user_roles',
  'webhook_replays',
  'webhook_delivery_attempts',
  'webhook_deliveries',
  'webhook_events',
  'webhook_subscriptions',
  'notification_alert_windows',
  'notification_settings',
  // Tenant configuration written by the api during a run (policies, scanning, DLP, BEC).
  'policy_actions',
  'policy_conditions',
  'policy_exceptions',
  'policy_versions',
  'email_policies',
  'policy_settings',
  'risk_scoring_profile_versions',
  'risk_scoring_profiles',
  'scan_engine_settings',
  'dlp_policy_rules',
  'dlp_policies',
  'dlp_exceptions',
  'dlp_custom_patterns',
  'dlp_keyword_dictionaries',
  'dlp_compliance_settings',
  'bec_feedback',
  'bec_suppression_rules',
  'bec_trusted_senders',
  'bec_vendor_profiles',
  'bec_executive_profiles',
  'bec_contact_history',
  'attachment_rescan_jobs',
  'threat_indicators',
  'yara_rules',
  'roles',
  'users',
  'organization_limits',
  'organization_features',
  'organization_settings',
  'organization_deployments',
] as const;

/** Partitioned rows of a run are never older than this (the seeder writes ≤ 7 days back). */
const PARTITION_CUTOFF_DAYS = 60;

function isForeignKeyError(error: unknown): boolean {
  const text = String((error as { message?: string }).message ?? error);
  return text.includes('1451') || text.includes('foreign key constraint');
}

async function deleteTable(
  prisma: PrismaClient,
  table: string,
  orgIds: readonly bigint[],
  cutoff: Date,
): Promise<number> {
  const column = PARTITION_COLUMN[table];
  const partition = column
    ? Prisma.sql` AND ${Prisma.raw(`\`${column}\``)} >= ${cutoff}`
    : Prisma.empty;
  return prisma.$executeRaw`DELETE FROM ${Prisma.raw(`\`${table}\``)}
    WHERE organization_id IN (${Prisma.join(orgIds)})${partition}`;
}

async function deleteObjects(orgIds: readonly bigint[]): Promise<number> {
  const { s3, bucket } = mailBucket();
  let deleted = 0;
  try {
    for (const id of orgIds) {
      let token: string | undefined;
      do {
        const page = await s3.send(
          new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: `org/${id.toString()}/`,
            ContinuationToken: token,
          }),
        );
        const keys = (page.Contents ?? []).flatMap((o) => (o.Key ? [{ Key: o.Key }] : []));
        if (keys.length > 0) {
          await s3.send(new DeleteObjectsCommand({ Bucket: bucket, Delete: { Objects: keys } }));
          deleted += keys.length;
        }
        token = page.IsTruncated ? page.NextContinuationToken : undefined;
      } while (token);
    }
  } finally {
    s3.destroy();
  }
  return deleted;
}

export interface CleanupResult {
  organizations: number;
  platformUsers: number;
  objects: number;
}

export async function cleanup(prisma: PrismaClient): Promise<CleanupResult> {
  const orgs = await prisma.organization.findMany({
    where: { slug: { startsWith: ORG_SLUG_PREFIX } },
    select: { id: true },
  });
  const orgIds = orgs.map((o) => o.id);
  const platformUsers = await prisma.user.findMany({
    where: {
      email: { endsWith: PLATFORM_EMAIL_SUFFIX },
      organization: { slug: PLATFORM_ORGANIZATION_SLUG },
    },
    select: { id: true },
  });
  const userIds = platformUsers.map((u) => u.id);

  if (userIds.length > 0) {
    const byUser = { userId: { in: userIds } };
    await prisma.loginAuditLog.deleteMany({ where: byUser });
    await prisma.userToken.deleteMany({ where: byUser });
    await prisma.userMfaRecoveryCode.deleteMany({ where: byUser });
    await prisma.userSession.deleteMany({ where: byUser });
    await prisma.userRole.deleteMany({ where: byUser });
    await prisma.user.deleteMany({ where: { id: { in: userIds } } });
  }
  await prisma.loginAuditLog.deleteMany({
    where: { emailAttempted: { endsWith: 'e2e-portal.test' } },
  });

  let objects = 0;
  if (orgIds.length > 0) {
    objects = await deleteObjects(orgIds);
    const cutoff = new Date(Date.now() - PARTITION_CUTOFF_DAYS * 86_400_000);
    let pending: string[] = [...ORDER];
    for (let pass = 0; pending.length > 0; pass++) {
      const failed: string[] = [];
      for (const table of pending) {
        try {
          await deleteTable(prisma, table, orgIds, cutoff);
        } catch (error) {
          if (!isForeignKeyError(error) || pass >= 4) throw error;
          failed.push(table);
        }
      }
      pending = failed;
    }
    // The notification-worker's digest scheduler may add a quarantine_digest_runs row for any
    // organization at any moment (Fixtures.cleanup): delete and retry a few times.
    for (let attempt = 0; ; attempt++) {
      await prisma.quarantineDigestRun.deleteMany({ where: { organizationId: { in: orgIds } } });
      await prisma.notificationAlertWindow.deleteMany({
        where: { organizationId: { in: orgIds } },
      });
      try {
        await prisma.organization.deleteMany({
          where: { id: { in: orgIds }, slug: { startsWith: ORG_SLUG_PREFIX } },
        });
        break;
      } catch (error) {
        if (!isForeignKeyError(error) || attempt >= 4) throw error;
      }
    }
  }
  return { organizations: orgIds.length, platformUsers: userIds.length, objects };
}
