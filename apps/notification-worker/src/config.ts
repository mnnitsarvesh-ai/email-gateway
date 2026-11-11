import {
  amqpUrlListSchema,
  baseConfigSchema,
  databaseConfigSchema,
  httpConfigSchema,
  loadConfig,
  notifySmtpFieldsSchema,
  validateNotifySmtpConfig,
} from '@email-gateway/config';
import { z } from 'zod';

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);

/**
 * notification-worker (step 5.2 §5, P25; docs/plan/steps/16-policy-engine.md): the writer
 * database, the `NOTIFY_SMTP_*` relay (as the api's transactional mail; plaintext only when
 * APP_ENV is local or ci), its broker user (`RABBITMQ_NOTIFICATION_URL`, eg-notification: read
 * `email.notifications`, write retry and dead-letter copies), the consumer's prefetch and
 * transaction budget (≥ 120 s, the 4.2 §6 rule), the alert recipient cap and the portal origin
 * the notices link to.
 */
export const configSchema = baseConfigSchema
  .extend(httpConfigSchema(3050).shape)
  .extend(databaseConfigSchema.shape)
  .extend(notifySmtpFieldsSchema.shape)
  .extend({
    /** amqp(s) URL(s) of the `eg-notification` broker user (comma list = cluster nodes). */
    RABBITMQ_NOTIFICATION_URL: amqpUrlListSchema,
    /** Unacknowledged `email.notifications` deliveries per replica. */
    NOTIFICATION_PREFETCH: int(1, 32).default(4),
    /** Budget of the consumer's idempotency transaction (the SMTP send runs inside it). */
    NOTIFICATION_DB_TX_TIMEOUT_MS: int(120_000, 600_000).default(120_000),
    /** Most administrators one policy alert is sent to (sorted by user id). */
    NOTIFICATION_MAX_RECIPIENTS: int(1, 500).default(50),
    /** Origin of the admin portal; notices link to `${PORTAL_PUBLIC_URL}/messages/<id>`. */
    PORTAL_PUBLIC_URL: z
      .url({ protocol: /^https?$/ })
      .transform((v) => v.replace(/\/+$/, ''))
      .default('http://localhost:3001'),
  })
  .superRefine((cfg, ctx) => {
    validateNotifySmtpConfig(cfg, ctx);
    if (
      (cfg.APP_ENV === 'staging' || cfg.APP_ENV === 'production') &&
      !cfg.PORTAL_PUBLIC_URL.startsWith('https://')
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['PORTAL_PUBLIC_URL'],
        message: 'must be an https:// URL when APP_ENV is staging or production',
      });
    }
  });

export type WorkerConfig = z.infer<typeof configSchema>;

export const loadWorkerConfig = (env: NodeJS.ProcessEnv = process.env): Readonly<WorkerConfig> =>
  loadConfig(configSchema, env);
