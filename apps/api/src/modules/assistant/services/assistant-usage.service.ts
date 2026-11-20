import { BadRequestException, Injectable } from '@nestjs/common';
import { costMicros } from '@email-gateway/assistant';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  USAGE_DEFAULT_RANGE_DAYS,
  USAGE_MAX_RANGE_DAYS,
  utcDayStart,
} from '../assistant.constants';
import type { UsageQuery, UsageRowView, UsageView } from '../dto/assistant.schemas';
import { UsageRepository } from '../repositories/usage.repository';
import { AssistantProviderService } from './assistant-provider.service';

const DAY_MS = 86_400_000;
const day = (date: Date): string => date.toISOString().slice(0, 10);

/**
 * `GET /assistant/usage` (design §4.1, D11): the organization's usage per UTC day, provider and
 * model between `from` and `to` (inclusive, at most 92 days; default the last 30 days), with
 * advisory costs (`null` for a model without a price). From the read replica.
 */
@Injectable()
export class AssistantUsageService {
  constructor(
    private readonly usage: UsageRepository,
    private readonly provider: AssistantProviderService,
  ) {}

  now(): Date {
    return new Date();
  }

  async get(scope: TenantScope, query: UsageQuery): Promise<UsageView> {
    const to = query.to ? new Date(`${query.to}T00:00:00.000Z`) : utcDayStart(this.now());
    const from = query.from
      ? new Date(`${query.from}T00:00:00.000Z`)
      : new Date(to.getTime() - (USAGE_DEFAULT_RANGE_DAYS - 1) * DAY_MS);
    if (from.getTime() > to.getTime()) {
      throw new BadRequestException(['from: must not be after to']);
    }
    if ((to.getTime() - from.getTime()) / DAY_MS + 1 > USAGE_MAX_RANGE_DAYS) {
      throw new BadRequestException([`to: the range is at most ${USAGE_MAX_RANGE_DAYS} days`]);
    }
    const rows = await this.usage.range(scope, from, to);
    const views: UsageRowView[] = rows.map((r) => ({
      day: day(r.day),
      provider: r.provider,
      model: r.model,
      turns: r.turns,
      inputTokens: Number(r.inputTokens),
      outputTokens: Number(r.outputTokens),
      cacheReadTokens: Number(r.cacheReadTokens),
      cacheWriteTokens: Number(r.cacheWriteTokens),
      costMicros: this.priced(r.model) ? Number(r.costMicros) : null,
    }));
    const sum = (
      key: 'turns' | 'inputTokens' | 'outputTokens' | 'cacheReadTokens' | 'cacheWriteTokens',
    ) => views.reduce((total, r) => total + r[key], 0);
    const priced = views.filter((r) => r.costMicros !== null);
    return {
      from: day(from),
      to: day(to),
      rows: views,
      totals: {
        turns: sum('turns'),
        inputTokens: sum('inputTokens'),
        outputTokens: sum('outputTokens'),
        cacheReadTokens: sum('cacheReadTokens'),
        cacheWriteTokens: sum('cacheWriteTokens'),
        costMicros:
          views.length === 0 || priced.length > 0
            ? priced.reduce((total, r) => total + (r.costMicros ?? 0), 0)
            : null,
      },
    };
  }

  private priced(model: string): boolean {
    const zero = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
    return costMicros(model, zero, this.provider.prices) !== null;
  }
}
