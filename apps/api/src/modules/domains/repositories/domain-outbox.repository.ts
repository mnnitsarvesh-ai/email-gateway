import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import {
  type DomainRoutingChangedV1,
  domainRoutingChangedV1,
  type DomainStatusChangedV1,
  domainStatusChangedV1,
  EventTypes,
} from '@email-gateway/event-contracts';
import { DOMAIN_AGGREGATE_TYPE } from '../domains.constants';

type Client = Prisma.TransactionClient;

const MAX_CORRELATION_ID = 128;

/**
 * Writes `domain.status.changed.v1` (D15) and `domain.routing.changed.v1` (step 2.3 R2) to
 * `message_outbox` in the transaction of the change they describe. The relay that publishes outbox rows arrives with step 3.2; until then the rows are the
 * contract and expire with the outbox partitions.
 */
@Injectable()
export class DomainOutboxRepository {
  async insertStatusChanged(
    tx: Client,
    event: { organizationId: bigint; correlationId: string; payload: DomainStatusChangedV1 },
  ): Promise<string> {
    const payload = domainStatusChangedV1.parse(event.payload);
    const eventId = randomUUID();
    await tx.messageOutbox.create({
      data: {
        eventId,
        organizationId: event.organizationId,
        eventType: EventTypes.DomainStatusChanged,
        aggregateType: DOMAIN_AGGREGATE_TYPE,
        aggregateId: payload.domainId,
        correlationId: event.correlationId.slice(0, MAX_CORRELATION_ID),
        payload,
      },
    });
    return eventId;
  }

  /**
   * `domain.routing.changed.v1` (step 2.3 R2): the domain's destination servers changed. The
   * smtp-adapter's outbox tail deletes the domain's transport answer and the TLS answers of
   * every named host (old and new).
   */
  async insertRoutingChanged(
    tx: Client,
    event: { organizationId: bigint; correlationId: string; payload: DomainRoutingChangedV1 },
  ): Promise<string> {
    const payload = domainRoutingChangedV1.parse(event.payload);
    const eventId = randomUUID();
    await tx.messageOutbox.create({
      data: {
        eventId,
        organizationId: event.organizationId,
        eventType: EventTypes.DomainRoutingChanged,
        aggregateType: DOMAIN_AGGREGATE_TYPE,
        aggregateId: payload.domainId,
        correlationId: event.correlationId.slice(0, MAX_CORRELATION_ID),
        payload,
      },
    });
    return eventId;
  }
}
