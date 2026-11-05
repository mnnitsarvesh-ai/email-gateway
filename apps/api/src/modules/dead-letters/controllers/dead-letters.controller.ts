import { Body, Controller, Get, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { RequireMfa, RequirePermissions, UserOnly } from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  type DeadLetterStats,
  DeadLetterStatsSchema,
  type ReplayRequest,
  ReplayRequestSchema,
  type ReplayResponse,
  ReplayResponseSchema,
} from '../dto/dead-letters.schemas';
import { REPLAYABLE_QUEUES } from '../domain/dead-letter-replay';
import { DeadLetterReplayService } from '../services/dead-letter-replay.service';

/** Platform permission of the replay (seed catalog, step 3.2 Q9). */
export const PLATFORM_DEAD_LETTER_REPLAY = 'platform:dead_letter_replay';
/** The replayable work queues of the topology (step 4.2: also `scan.attachment`). */
const REPLAYABLE_LIST = REPLAYABLE_QUEUES.map((queue) => `\`${queue}\``).join(', ');

/** Platform permission of the read-only queue view. */
export const PLATFORM_OPERATIONS = 'platform:operations';

/**
 * Dead letters of the pipeline queues (step 3.2 Q9): the depth of `email.dead-letter` and the
 * audited replay into a work queue. Platform users only (no API keys, no override tokens); the
 * replay needs an MFA session. The logic is in `DeadLetterReplayService`.
 */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'platform/dead-letters', version: '1' })
export class DeadLettersController {
  constructor(private readonly replays: DeadLetterReplayService) {}

  @Get()
  @RequirePermissions(PLATFORM_OPERATIONS)
  @ApiOperation({
    summary: 'Depth of the dead-letter queue',
    description:
      'Ready messages and consumers of `email.dead-letter` (passive check). 503 ' +
      '`dead_letter_replay_unavailable` when RABBITMQ_OPS_URL is not configured or the broker ' +
      'is unreachable.',
  })
  @ApiOkResponse({ schema: zodToOpenApi(DeadLetterStatsSchema) })
  @ApiErrors(401, 403, 503)
  stats(): Promise<DeadLetterStats> {
    return this.replays.stats();
  }

  @Post('replay')
  @RequirePermissions(PLATFORM_DEAD_LETTER_REPLAY)
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Replay dead letters into a work queue',
    description:
      `Fetches up to \`limit\` dead letters of \`sourceQueue\` (a work queue: ${REPLAYABLE_LIST}; ` +
      'other queues are 400 `source_queue_not_replayable`) matching ' +
      'the optional filters, republishes each unchanged envelope to the source queue with ' +
      'fresh retry headers and a replay id, confirmed before the dead letter is removed. ' +
      'Non-matching and invalid messages stay in the queue. A replayed event that was already ' +
      'processed is a ledger duplicate, so replays are safe to repeat. `dryRun` changes ' +
      'nothing. One replay at a time platform-wide (409 `replay_in_progress`); audited as ' +
      '`platform.dead_letters_replayed`. 503 `dead_letter_replay_unavailable` without ' +
      'RABBITMQ_OPS_URL or when the broker fails (the audit row then says `partial`).',
  })
  @ApiBody({ schema: zodToOpenApi(ReplayRequestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(ReplayResponseSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 503)
  replay(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(ReplayRequestSchema)) body: ReplayRequest,
    @Client() client: ClientContext,
  ): Promise<ReplayResponse> {
    return this.replays.replay(principal, body, client);
  }
}
