import {
  Body,
  Controller,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../../http/coded-exception';
import { CURSOR_INVALID } from '../../../http/cursor/cursor-codec';
import { INCONSISTENT_READ } from '../../../http/listing/echo-check';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiMessageNotFound } from '../api-docs';
import { MESSAGE_EXAMPLES } from '../dto/message-data.examples';
import {
  MESSAGE_REVEAL_MAX_IDS,
  type RevealBody,
  RevealBodySchema,
  type RevealManyBody,
  RevealManyBodySchema,
  type RevealManyResponse,
  RevealManyResponseSchema,
  type RevealResponse,
  RevealResponseSchema,
} from '../dto/message-sensitive.schemas';
import { MessageRevealRateLimit } from '../message-reveal-rate-limit';
import { SERVICE_UNAVAILABLE } from '../messages.errors';
import { MessageRevealService } from '../services/message-reveal.service';

/** Permission of the audited reveal operations (step 7.2 §2 E5, seeded by WP1). */
export const MESSAGE_REVEAL = 'message:reveal';

const NO_STORE = 'no-store';
const NO_STORE_HEADER = {
  'Cache-Control': {
    description: 'Never cache, log or forward a reveal response',
    schema: { type: 'string', enum: [NO_STORE] },
  },
};

/** The rules both reveal operations share, for the operation descriptions. */
const REVEAL_RULES =
  'Requires `message:reveal` (user tokens and API keys holding it; platform override sessions ' +
  'are audited with the override). Values are read from the read replica, then one ' +
  '`message.revealed` audit row per revealed message (resource `message`/`<id>`; the fields and ' +
  'counts, never the values) is committed on the writer **before** the response is sent; if ' +
  'that write fails the answer is `503 service_unavailable` and no value is returned. ' +
  '`Cache-Control: no-store`: never cache, log or forward the response. Both reveal operations ' +
  'share one per-user/API-key limit of API_MESSAGES_REVEAL_PER_MINUTE (default 30) requests per ' +
  'minute (`429 rate_limited` with `Retry-After`). No Idempotency-Key (a read with an audit ' +
  'record, repeated calls are new reveals). Values are attacker-controlled text, returned as ' +
  'stored.';

const Api403 = (): MethodDecorator =>
  ApiCodedError(403, 'Missing `message:reveal` (`forbidden`)', ['forbidden']);

const Api429 = (): MethodDecorator =>
  ApiCodedError(
    429,
    'More than API_MESSAGES_REVEAL_PER_MINUTE reveals by this user or API key in the current ' +
      'minute (`scope: route`; `Retry-After` gives the seconds to wait), or a global limit ' +
      '(`scope: principal | tenant`)',
    ['rate_limited'],
    { scope: { type: 'string', enum: ['principal', 'tenant', 'route'] } },
  );

const Api503 = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The audit rows could not be written (`service_unavailable`, no value returned), the ' +
      'rate-limit store is unavailable (`service_unavailable`), or the replica returned a row ' +
      'that does not echo the query (`inconsistent_read`); retry',
    [SERVICE_UNAVAILABLE, INCONSISTENT_READ],
  );

/**
 * The audited reveal operations of the message surface (step 7.2 §2 E6, ADR-0062): subjects of a
 * page of messages and the subject, To/Cc/Subject header values and recipient addresses of one
 * message. Translation only; the logic is in MessageRevealService.
 */
@ApiTags('messages')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'messages', version: '1' })
export class MessageRevealController {
  constructor(private readonly reveals: MessageRevealService) {}

  @Post('reveal')
  @RequirePermissions(MESSAGE_REVEAL)
  @MessageRevealRateLimit()
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Reveal the subjects of messages',
    description:
      `The stored subjects of up to ${MESSAGE_REVEAL_MAX_IDS} messages of your organization ` +
      '(`messageIds`, distinct; e.g. one explorer page), in request order. Unknown ids and ids ' +
      'of other organizations are omitted from `data` (they look the same). One audit row ' +
      '`message.revealed` per revealed message (`metadata: { fields: ["subject"], bulk: true ' +
      '}`). ' +
      REVEAL_RULES,
  })
  @ApiBody({
    schema: zodToOpenApi(RevealManyBodySchema, { io: 'input' }),
    examples: { page: { value: MESSAGE_EXAMPLES.revealManyBody } },
  })
  @ApiOkResponse({
    description: 'The revealed subjects',
    schema: { ...zodToOpenApi(RevealManyResponseSchema), example: MESSAGE_EXAMPLES.revealMany },
    headers: NO_STORE_HEADER,
  })
  @ApiCodedError(
    400,
    '`validation_failed`: the body is not strict JSON of the documented shape (1-100 distinct ' +
      'UUIDs; `message` lists `"<path>: <issue>"`)',
    ['validation_failed'],
  )
  @ApiErrors(401)
  @Api403()
  @Api429()
  @Api503()
  revealMany(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(RevealManyBodySchema)) body: RevealManyBody,
    @Client() client: ClientContext,
  ): Promise<RevealManyResponse> {
    return this.reveals.revealMany(principal, scope, body, client.ip);
  }

  @Post(':messageId/reveal')
  @RequirePermissions(MESSAGE_REVEAL)
  @MessageRevealRateLimit()
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Reveal the masked metadata of a message',
    description:
      'The clear values the reads withhold, per `fields`: `subject` (the stored subject or ' +
      'null), `headers` (the stored To, Cc and Subject rows in `seq` order) and `recipients` ' +
      '(one page of the envelope recipients in RCPT order with the matched user’s public id; ' +
      '`recipientsLimit` 1-100, default 100; continue with `recipientsCursor` = ' +
      '`recipients.nextCursor`, a signed v1 cursor bound to this message and your organization: ' +
      'any other is `400 cursor_invalid`). `recipientsCursor` and `recipientsLimit` are refused ' +
      'without `recipients`. Addresses inside SMTP replies, delivery event details and Rspamd ' +
      'symbol options stay masked (match deliveries by `rcptSeq`). One audit row ' +
      '`message.revealed` (`metadata: { fields, headerCount?, recipients?: { count, ' +
      'firstRcptSeq, lastRcptSeq } }`). Unknown ids and ids of other organizations are ' +
      '`404 message_not_found`. ' +
      REVEAL_RULES,
  })
  @ApiMessageId()
  @ApiBody({
    schema: zodToOpenApi(RevealBodySchema, { io: 'input' }),
    examples: {
      all: { value: MESSAGE_EXAMPLES.revealBody },
      moreRecipients: { value: MESSAGE_EXAMPLES.revealMoreRecipientsBody },
    },
  })
  @ApiOkResponse({
    description: 'The revealed values of the requested fields',
    schema: { ...zodToOpenApi(RevealResponseSchema), example: MESSAGE_EXAMPLES.reveal },
    headers: NO_STORE_HEADER,
  })
  @ApiCodedError(
    400,
    '`validation_failed` (`messageId` is not a UUID, or the body is not strict JSON of the ' +
      'documented shape; `message` lists `"<path>: <issue>"`) or `cursor_invalid` (the ' +
      '`recipientsCursor` is invalid, expired, of another message or of another organization)',
    ['validation_failed', CURSOR_INVALID],
  )
  @ApiErrors(401)
  @Api403()
  @ApiMessageNotFound()
  @Api429()
  @Api503()
  reveal(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Body(new ZodValidationPipe(RevealBodySchema)) body: RevealBody,
    @Client() client: ClientContext,
  ): Promise<RevealResponse> {
    return this.reveals.reveal(principal, scope, messageId, body, client.ip);
  }
}
