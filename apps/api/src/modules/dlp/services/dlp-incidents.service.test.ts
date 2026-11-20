import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { NO_DLP_IDS } from '../domain/dlp-result';
import type {
  DlpResultRow,
  DlpResultsRepository,
  IncidentPage,
} from '../repositories/dlp-results.repository';
import { decodeIncidentCursor, DlpIncidentsService } from './dlp-incidents.service';

const scope = systemScope(7n);
const BASE = Date.UTC(2026, 10, 20, 10, 0, 0);

/** Result rows newest first; even ids belong to gateway messages, odd ids to intake messages. */
function row(id: number): DlpResultRow {
  return {
    id: BigInt(id),
    scanId: BigInt(1000 + id),
    receivedAt: new Date(BASE + id * 1000),
    messageId: BigInt(500 + id),
    lifecycleRound: 0,
    direction: 'outbound',
    engineVersion: 'dlp/1',
    rulesVersion: 'dlp-map/1',
    settingsVersion: 's',
    policyVersion: 'p',
    extractorVersion: 'dlp-extract/1',
    verdict: 'suspicious',
    action: 'block',
    actionSource: 'default_policy',
    matchedPolicyId: null,
    matchedRuleId: null,
    coverage: 'complete',
    coverageDetail: {},
    categories: [],
    findings: [],
    policy: { winner: null, matched: [], exceptionsApplied: [] },
    findingCount: 0,
    evidenceStatus: 'none',
    createdAt: new Date(BASE + id * 1000),
  } as unknown as DlpResultRow;
}

function setup(ids: number[]) {
  const rows = ids.map(row).sort((a, b) => Number(b.id - a.id));
  const repository = {
    listIncidents: vi.fn((_s: unknown, p: IncidentPage) =>
      Promise.resolve(
        rows.filter((r) => p.before === undefined || r.id < p.before.id).slice(0, p.take),
      ),
    ),
    // The repository maps gateway messages only (step 8.6 D5).
    messagePublicIds: vi.fn((_s: unknown, keys: ReadonlyArray<{ messageId: bigint }>) =>
      Promise.resolve(
        new Map(
          keys
            .filter((k) => (k.messageId - 500n) % 2n === 0n)
            .map((k) => [k.messageId.toString(), `msg-${k.messageId.toString()}`]),
        ),
      ),
    ),
    publicIds: vi.fn(() => Promise.resolve(NO_DLP_IDS)),
  };
  return {
    service: new DlpIncidentsService(repository as unknown as DlpResultsRepository),
    repository,
  };
}

describe('DlpIncidentsService.list without journal intake results (step 8.6 D5)', () => {
  it('drops intake results and refills the page from the following rows', async () => {
    const t = setup([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const page = await t.service.list(scope, { limit: 3 });
    expect(page.data.map((d) => d.messageId)).toEqual(['msg-510', 'msg-508', 'msg-506']);
    expect(page.nextCursor).not.toBeNull();
    expect(decodeIncidentCursor(page.nextCursor!).id).toBe(6n);
    expect(t.repository.listIncidents).toHaveBeenCalledTimes(2);
    const next = await t.service.list(scope, { limit: 3, cursor: page.nextCursor! });
    expect(next.data.map((d) => d.messageId)).toEqual(['msg-504', 'msg-502']);
    expect(next.nextCursor).toBeNull();
  });

  it('an organization with intake results only gets an empty list', async () => {
    const t = setup([1, 3, 5]);
    const page = await t.service.list(scope, { limit: 25 });
    expect(page).toEqual({ data: [], nextCursor: null });
  });

  it('stops after five reads and hands out the cursor of the last row read', async () => {
    const t = setup(Array.from({ length: 40 }, (_, i) => 2 * i + 1));
    const page = await t.service.list(scope, { limit: 2 });
    expect(page.data).toEqual([]);
    expect(t.repository.listIncidents).toHaveBeenCalledTimes(5);
    // 5 reads of 3 rows from id 79 down: the last row read is id 51.
    expect(decodeIncidentCursor(page.nextCursor!).id).toBe(51n);
  });
});
