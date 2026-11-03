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
  rabbitmqUrl: () => required('RABBITMQ_URL'),
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
