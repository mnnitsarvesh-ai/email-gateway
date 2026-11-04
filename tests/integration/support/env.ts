/** Connection details for the compose stack as seen from the host (127.0.0.1 + host ports). */
function required(key: string): string {
  const value = process.env[key];
  if (!value)
    throw new Error(`${key} is not set. Run \`pnpm env:init\` and start the stack first.`);
  return value;
}

const port = (key: string, fallback: number): number => Number(process.env[key] ?? fallback);

export const stack = {
  host: '127.0.0.1',
  databaseUrl: () => required('DATABASE_URL'),
  /** Migrator account (DDL), used by the partition maintenance tests. */
  migrationDatabaseUrl: () => required('MIGRATION_DATABASE_URL'),
  /** Reader account on the replica (SELECT + REPLICATION CLIENT). */
  databaseReadUrl: () => required('DATABASE_READ_URL'),
  /** Administrator on vhost `/` (tests and tools only, step 3.2 Q10). Never logged. */
  rabbitmqUrl: () => required('RABBITMQ_URL'),
  /** Management HTTP API base URL (no credentials). */
  rabbitmqMgmtUrl: () => required('RABBITMQ_MGMT_URL'),
  /** Topology v1 vhost (`email-gateway`). */
  rabbitmqVhost: () => process.env.RABBITMQ_VHOST || 'email-gateway',
  /** Administrator credentials for the management API (header only, never logged). */
  rabbitmqAdmin: () => ({
    user: required('RABBITMQ_USER'),
    password: required('RABBITMQ_PASSWORD'),
  }),
  /** Least-privilege role URLs on the topology vhost (step 3.2 Q10). Never logged. */
  rabbitmqRoleUrls: () => ({
    relay: required('RABBITMQ_RELAY_URL'),
    emailWorker: required('RABBITMQ_EMAIL_WORKER_URL'),
    deliveryWorker: required('RABBITMQ_DELIVERY_WORKER_URL'),
    ops: required('RABBITMQ_OPS_URL'),
  }),
  redisUrl: () => required('REDIS_URL'),
  s3: () => ({
    endpoint: required('S3_ENDPOINT'),
    region: required('S3_REGION'),
    accessKeyId: required('S3_ACCESS_KEY_ID'),
    secretAccessKey: required('S3_SECRET_ACCESS_KEY'),
    mailBucket: required('S3_BUCKET_MAIL'),
    archiveBucket: required('S3_BUCKET_ARCHIVE'),
  }),
  /** Compose project name (docker compose -p); the same default as docker-compose.yml. */
  composeProject: () => process.env.COMPOSE_PROJECT_NAME || 'email-gateway',
  ports: {
    mysql: port('MYSQL_HOST_PORT', 3306),
    mysqlReplica: port('MYSQL_REPLICA_HOST_PORT', 3308),
    /** Inbound MX (postfix:25). */
    smtp: port('SMTP_HOST_PORT', 2525),
    /** postfix-outbound submission (587). */
    submission: port('SUBMISSION_HOST_PORT', 2587),
    /** postfix-outbound connector relay (25). */
    outboundRelay: port('OUTBOUND_RELAY_HOST_PORT', 2527),
    redisDkim: port('REDIS_DKIM_HOST_PORT', 6391),
    rspamd: port('RSPAMD_HOST_PORT', 11333),
    clamav: port('CLAMAV_HOST_PORT', 3310),
    services: {
      api: port('API_HOST_PORT', 3000),
      'admin-portal': port('ADMIN_PORTAL_HOST_PORT', 3001),
      'smtp-adapter': port('SMTP_ADAPTER_HOST_PORT', 3010),
      'email-worker': port('EMAIL_WORKER_HOST_PORT', 3020),
      'policy-engine': port('POLICY_ENGINE_HOST_PORT', 3030),
      'delivery-worker': port('DELIVERY_WORKER_HOST_PORT', 3040),
      'notification-worker': port('NOTIFICATION_WORKER_HOST_PORT', 3050),
      'archive-worker': port('ARCHIVE_WORKER_HOST_PORT', 3060),
      /** Outbox relay and reconciler (step 3.2 Q11/Q12). */
      'event-relay': port('EVENT_RELAY_HOST_PORT', 3070),
    },
  },
};

/**
 * True when smtp-adapter answers its liveness probe, as a container of the `apps` profile or on
 * the host (`pnpm --filter @email-gateway/smtp-adapter dev`, step 2.2 D20).
 */
export async function adapterRunning(): Promise<boolean> {
  try {
    const res = await fetch(
      `http://${stack.host}:${stack.ports.services['smtp-adapter']}/health/live`,
      {
        signal: AbortSignal.timeout(1_000),
      },
    );
    return res.ok;
  } catch {
    return false;
  }
}
