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
  relayDomain: () => (process.env.POSTFIX_RELAY_DOMAINS ?? 'gateway.test').split(',')[0]!.trim(),
  ports: {
    mysql: port('MYSQL_HOST_PORT', 3306),
    mysqlReplica: port('MYSQL_REPLICA_HOST_PORT', 3308),
    smtp: port('SMTP_HOST_PORT', 2525),
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

/** True when the `apps` compose profile is running (smtp-adapter answers its probe). */
export async function appsRunning(): Promise<boolean> {
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
