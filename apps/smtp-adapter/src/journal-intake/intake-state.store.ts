import { Injectable } from '@nestjs/common';
import { RedisService } from '@email-gateway/common';
import { z } from 'zod';
import { LuaScript } from '../rate-limit/lua-script';

/** D2.2.5: the transaction kind lives one hour (longer than any SMTP transaction). */
export const INTAKE_INSTANCE_TTL_SECONDS = 3600;
/**
 * The END-OF-MESSAGE marker of an intake queue file outlives Postfix's `maximal_queue_lifetime`
 * (5 days): every LMTP retry of the queue file must find it (like the 8.2 relay marker).
 */
export const INTAKE_MARKER_TTL_SECONDS = 432_000;

/** Postfix `instance` and queue id shapes (bounded before they become keys). */
const INSTANCE = /^[A-Za-z0-9._-]{1,64}$/;
const QUEUE_ID = /^[A-Za-z0-9]{1,32}$/;

/** `sa:jintake:inst:<instance>`: the destination kind of one SMTP transaction. */
export const intakeInstanceKey = (instance: string): string => `sa:jintake:inst:${instance}`;
/** `sa:jintake:q:<queueId>`: the TLS / certificate facts of an intake queue file. */
export const intakeMarkerKey = (queueId: string): string => `sa:jintake:q:${queueId}`;

/** `src:<sourceId>` (one intake source) or `tenant` (tenant domains). */
export type TransactionKind = `src:${string}` | 'tenant';

/**
 * Sets the kind on the first recipient (with the TTL) and returns the stored kind; a later
 * recipient of the same transaction compares against it (KEYS[1], ARGV[1] kind, ARGV[2] TTL).
 */
const CLAIM = new LuaScript(`
local current = redis.call('GET', KEYS[1])
if not current then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
  return ARGV[1]
end
return current
`);

export class InvalidIntakeKeyError extends Error {}

/**
 * Marker v1 of an intake queue file (contracts §34 addition, written by the policy service at
 * END-OF-MESSAGE, read by the journal LMTP re-check): the SMTP session's TLS facts and the
 * client certificate fingerprints it presented. XFORWARD carries the client address but no TLS
 * facts, so without the marker the LMTP could not re-check `requireTls` and certificates.
 */
export const intakeMarkerSchema = z
  .object({
    v: z.literal(1),
    sourceId: z.string().regex(/^\d{1,20}$/),
    tls: z.boolean(),
    tlsProtocol: z.string().max(16).nullable(),
    certFingerprints: z.array(z.string().regex(/^[0-9a-f]{64}$/)).max(2),
    clientAddress: z.string().max(45),
  })
  .strict();
export type IntakeMarker = z.infer<typeof intakeMarkerSchema>;

/**
 * Redis state of the intake policy (step 8.6 D2.2.5 and the END-OF-MESSAGE marker). Every Redis
 * error propagates: the policy answers `DEFER_IF_PERMIT 4.3.5`, the LMTP `451` (fail closed).
 */
@Injectable()
export class IntakeStateStore {
  constructor(private readonly redis: RedisService) {}

  /**
   * Claims the transaction for `kind`: true when the transaction had no kind yet or the same
   * one; false when another kind was recorded (D2.2.5, `INTAKE_ONE_DESTINATION`).
   */
  async claim(instance: string, kind: TransactionKind): Promise<boolean> {
    if (!INSTANCE.test(instance)) throw new InvalidIntakeKeyError('invalid policy instance');
    const stored = await CLAIM.run(
      this.redis.client,
      [intakeInstanceKey(instance)],
      [kind, INTAKE_INSTANCE_TTL_SECONDS],
    );
    return stored === kind;
  }

  /** The kind recorded for a transaction, or null. */
  async kindOf(instance: string): Promise<TransactionKind | null> {
    if (!INSTANCE.test(instance)) throw new InvalidIntakeKeyError('invalid policy instance');
    const raw = await this.redis.client.get(intakeInstanceKey(instance));
    if (raw === null) return null;
    if (raw === 'tenant' || /^src:\d{1,20}$/.test(raw)) return raw as TransactionKind;
    throw new Error('corrupt journal intake transaction state');
  }

  async writeMarker(queueId: string, marker: IntakeMarker): Promise<void> {
    if (!QUEUE_ID.test(queueId)) throw new InvalidIntakeKeyError('invalid queue id');
    await this.redis.client.set(
      intakeMarkerKey(queueId),
      JSON.stringify(intakeMarkerSchema.parse(marker)),
      'EX',
      INTAKE_MARKER_TTL_SECONDS,
    );
  }

  /** The marker of a queue file, or null. A value that does not parse throws (never "none"). */
  async readMarker(queueId: string): Promise<IntakeMarker | null> {
    if (!QUEUE_ID.test(queueId)) return null;
    const raw = await this.redis.client.get(intakeMarkerKey(queueId));
    if (raw === null) return null;
    return intakeMarkerSchema.parse(JSON.parse(raw));
  }
}
