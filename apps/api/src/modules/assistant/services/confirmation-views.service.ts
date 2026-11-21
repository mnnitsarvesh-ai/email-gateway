import { Injectable } from '@nestjs/common';
import type { ConfirmationView } from '@email-gateway/assistant';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { confirmationView } from '../domain/views';
import { ConfirmationsRepository } from '../repositories/confirmations.repository';
import type { Owner } from '../repositories/conversations.repository';
import { AssistantLimitsService } from './assistant-limits.service';

/**
 * Confirmation views of stored proposal executions (step AI-2 D7 `ExecutionView.confirmation`):
 * the messages route, turn results and `GET /assistant/executions/{id}`. Never the token.
 * `reauthFresh` is the viewing session's re-authentication window (one Redis read per call).
 */
@Injectable()
export class ConfirmationViewsService {
  constructor(
    private readonly confirmations: ConfirmationsRepository,
    private readonly limits: AssistantLimitsService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** Views by proposal execution id (internal). */
  async forExecutions(
    principal: UserPrincipal,
    owner: Owner,
    executionIds: readonly bigint[],
    on: 'writer' | 'replica' = 'writer',
  ): Promise<Map<bigint, ConfirmationView>> {
    const out = new Map<bigint, ConfirmationView>();
    if (executionIds.length === 0) return out;
    const rows = await this.confirmations.forExecutions(owner, executionIds, on);
    if (rows.length === 0) return out;
    const fresh = rows.some((row) => row.requiresReauth)
      ? await this.limits.reauthFresh(principal.sessionId)
      : false;
    const now = this.now();
    for (const row of rows) {
      out.set(
        row.executionId,
        confirmationView(row, now, fresh && row.sessionFamilyId === principal.sessionId),
      );
    }
    return out;
  }
}
