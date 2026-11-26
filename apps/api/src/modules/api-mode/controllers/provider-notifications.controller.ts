import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import { Public } from '../../../auth-contracts/decorators';
import { ApiCodedError } from '../../../http/coded-exception';
import { NotificationRateLimitGuard } from '../notification-rate-limit.guard';
import {
  type CallbackOutcome,
  ProviderNotificationsService,
} from '../services/provider-notifications.service';

const HANDSHAKE =
  ' With `?validationToken=…` (Graph’s subscription validation handshake; 1-1024 printable ' +
  'characters) the token is echoed as `200 text/plain; charset=utf-8` with ' +
  '`X-Content-Type-Options: nosniff`.';

const RULES =
  ' Otherwise the body is a Graph notification collection `{ value: [1..1000 items] }`; each ' +
  'item selects a mailbox only through its stored subscription id plus a constant-time match of ' +
  'its `clientState` against the stored hash and, when present, its `tenantId` against the ' +
  'connection’s bound tenant, and only requests a delta sync of that mailbox (resource data and ' +
  'content are ignored). The answer is always `202` with an empty body, whatever matched (no ' +
  'oracle about subscriptions). JSON bodies up to 256 KiB (`413` above); ' +
  'API_MODE_NOTIFICATION_RATE_PER_MINUTE requests per minute per client IP (`429 rate_limited` ' +
  'with `Retry-After`). Public: no credential (called by Microsoft Graph).';

const NOTIFICATION_BODY = {
  type: 'object',
  properties: {
    value: {
      type: 'array',
      minItems: 1,
      maxItems: 1000,
      items: {
        type: 'object',
        properties: {
          subscriptionId: { type: 'string' },
          clientState: { type: 'string' },
          changeType: { type: 'string' },
          lifecycleEvent: {
            type: 'string',
            enum: ['reauthorizationRequired', 'subscriptionRemoved', 'missed'],
          },
          tenantId: { type: 'string' },
          subscriptionExpirationDateTime: { type: 'string' },
        },
        required: ['subscriptionId'],
      },
    },
  },
  required: ['value'],
};

const EXAMPLE_ITEM = {
  subscriptionId: '00000000-0000-0000-0000-00000000aaaa',
  clientState: 'example-client-state-placeholder',
  tenantId: '11111111-2222-3333-4444-555555555555',
};

/** Renders the outcome: the handshake echo or `202` with no body. */
function send(res: Response, outcome: CallbackOutcome): void {
  if (outcome.kind === 'echo') {
    res
      .status(HttpStatus.OK)
      .setHeader('Content-Type', 'text/plain; charset=utf-8')
      .setHeader('X-Content-Type-Options', 'nosniff')
      .send(outcome.token);
    return;
  }
  res.status(HttpStatus.ACCEPTED).end();
}

/**
 * The public Microsoft Graph change and lifecycle notification callbacks of API-mode change feeds
 * (step API-1 D10.4, D12.4; N3). Unprivileged: an item can only request a delta sync of the
 * mailbox its stored subscription id and client state select. Translation only.
 */
@ApiTags('provider-notifications')
@Controller({ path: 'provider-notifications', version: '1' })
export class ProviderNotificationsController {
  constructor(private readonly notifications: ProviderNotificationsService) {}

  @Post('graph')
  @Public()
  @UseGuards(NotificationRateLimitGuard)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Receive Microsoft Graph change notifications',
    description: 'The `notificationUrl` of API-mode Graph subscriptions.' + HANDSHAKE + RULES,
  })
  @ApiQuery({
    name: 'validationToken',
    required: false,
    description: 'Graph’s validation token (echoed as text/plain)',
    schema: { type: 'string', maxLength: 1024 },
  })
  @ApiBody({
    required: false,
    schema: NOTIFICATION_BODY,
    examples: { change: { value: { value: [{ ...EXAMPLE_ITEM, changeType: 'created' }] } } },
  })
  @ApiResponse({
    status: 200,
    description: 'The validation handshake: the token echoed',
    content: { 'text/plain': { schema: { type: 'string' }, example: 'example-validation-token' } },
  })
  @ApiResponse({ status: 202, description: 'Accepted (always; no body)' })
  @ApiCodedError(413, 'The body is larger than 256 KiB', ['payload_too_large'])
  @ApiCodedError(429, 'Too many requests from this client IP (`Retry-After`)', ['rate_limited'])
  async graph(
    @Query('validationToken') validationToken: unknown,
    @Body() body: unknown,
    @Res() res: Response,
  ): Promise<void> {
    send(res, await this.notifications.handle('change', validationToken, body));
  }

  @Post('graph/lifecycle')
  @Public()
  @UseGuards(NotificationRateLimitGuard)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Receive Microsoft Graph lifecycle notifications',
    description:
      'The `lifecycleNotificationUrl` of API-mode Graph subscriptions: `reauthorizationRequired` ' +
      '(the worker renews the subscription), `subscriptionRemoved` (it is re-created) and ' +
      '`missed` (a delta sync catches up); each also requests a sync.' +
      HANDSHAKE +
      RULES,
  })
  @ApiQuery({
    name: 'validationToken',
    required: false,
    description: 'Graph’s validation token (echoed as text/plain)',
    schema: { type: 'string', maxLength: 1024 },
  })
  @ApiBody({
    required: false,
    schema: NOTIFICATION_BODY,
    examples: {
      reauthorize: {
        value: { value: [{ ...EXAMPLE_ITEM, lifecycleEvent: 'reauthorizationRequired' }] },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'The validation handshake: the token echoed',
    content: { 'text/plain': { schema: { type: 'string' }, example: 'example-validation-token' } },
  })
  @ApiResponse({ status: 202, description: 'Accepted (always; no body)' })
  @ApiCodedError(413, 'The body is larger than 256 KiB', ['payload_too_large'])
  @ApiCodedError(429, 'Too many requests from this client IP (`Retry-After`)', ['rate_limited'])
  async lifecycle(
    @Query('validationToken') validationToken: unknown,
    @Body() body: unknown,
    @Res() res: Response,
  ): Promise<void> {
    send(res, await this.notifications.handle('lifecycle', validationToken, body));
  }
}
