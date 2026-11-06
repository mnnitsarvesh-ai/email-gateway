import { randomUUID } from 'node:crypto';
import {
  EventTypes,
  urlInspectionCompletedV1,
  type EventEnvelope,
  type UrlInspectionCompletedV1,
  type UrlInspectionRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { normalizeUrl } from '@email-gateway/url-security';
import type { InspectionOutcome } from '../browser/inspector';
import { emptySignals } from '../browser/signals';

/** Runs one inspection (the pool + inspector in production, a fake in unit tests). */
export type Inspect = (url: string) => Promise<InspectionOutcome>;

/** Publishes one envelope with publisher confirms; throws unless confirmed. */
export type PublishConfirmed = (envelope: EventEnvelope) => Promise<void>;

export interface HandlerDeps {
  inspect: Inspect;
  publish: PublishConfirmed;
  logger: Logger;
  workerVersion: string;
  browserVersion: () => string;
  onJob?: (result: string, seconds: number) => void;
  now?: () => number;
  newEventId?: () => string;
}

/** http(s), parseable, ≤ 2048, no userinfo — re-checked although the event schema did it. */
export function inspectableUrl(url: string): boolean {
  if (url.length > 2048) return false;
  const result = normalizeUrl(url);
  if (!result.ok) return false;
  try {
    const parsed = new URL(url);
    return (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      !parsed.username &&
      !parsed.password
    );
  } catch {
    return false;
  }
}

/**
 * Handler of `mail.url.inspection_requested.v1` (U15): strict validation (the consumer already
 * parsed the registered schema; the URL is re-checked), deadline check (a passed deadline is
 * reported as `failed`/`deadline_passed` without navigating), the inspection, then
 * `mail.url.inspection_completed.v1` published to `email.security` with routing key
 * `org.<orgId>.mail.url.inspection_completed.v1` (the envelope's organization copied from the
 * request) with publisher confirms. The handler resolves only after the confirm, so the request
 * is acked only then; a failed publish throws (retry hop). Stateless: results are deduplicated
 * by `inspectionId` in `scan.url.results`.
 */
export function inspectionHandler(deps: HandlerDeps) {
  const now = deps.now ?? Date.now;
  return async (event: EventEnvelope<UrlInspectionRequestedV1>): Promise<'handled'> => {
    const request = event.payload;
    const started = now();
    let outcome: InspectionOutcome;
    if (Date.parse(request.deadlineAt) <= started) {
      outcome = failedOutcome('deadline_passed');
    } else if (!inspectableUrl(request.url)) {
      outcome = failedOutcome('invalid_url');
    } else {
      outcome = await deps.inspect(request.url);
    }
    const errorCode =
      outcome.status === 'failed' ? (outcome.errorCode ?? 'navigation_failed') : null;
    deps.onJob?.(errorCode ?? 'completed', (now() - started) / 1000);
    const payload: UrlInspectionCompletedV1 = urlInspectionCompletedV1.parse({
      inspectionId: request.inspectionId,
      messageId: request.messageId,
      receivedAt: request.receivedAt,
      urlSeq: request.urlSeq,
      urlSha256: request.urlSha256,
      status: errorCode === null ? 'completed' : 'failed',
      errorCode,
      workerVersion: deps.workerVersion,
      browserVersion: deps.browserVersion(),
      finalUrlSha256: outcome.finalUrlSha256,
      finalHost: outcome.finalHost,
      navigations: outcome.navigations,
      signals: outcome.signals,
      durationMs: Math.max(0, Math.round(outcome.durationMs)),
      completedAt: new Date(now()).toISOString(),
    });
    deps.logger.info(
      {
        inspectionId: request.inspectionId,
        messageId: request.messageId,
        urlSeq: request.urlSeq,
        status: payload.status,
        errorCode,
        navigations: payload.navigations.length,
        blockedRequests: payload.signals.blockedRequests,
        durationMs: payload.durationMs,
      },
      'inspection finished',
    );
    await deps.publish({
      eventId: deps.newEventId?.() ?? randomUUID(),
      eventType: EventTypes.UrlInspectionCompleted,
      occurredAt: new Date(now()).toISOString(),
      correlationId: event.correlationId,
      organizationId: event.organizationId,
      payload,
    });
    return 'handled';
  };
}

function failedOutcome(code: 'deadline_passed' | 'invalid_url'): InspectionOutcome {
  return {
    status: 'failed',
    errorCode: code,
    navigations: [],
    signals: emptySignals(),
    finalUrlSha256: null,
    finalHost: null,
    durationMs: 0,
    crashed: false,
  };
}
