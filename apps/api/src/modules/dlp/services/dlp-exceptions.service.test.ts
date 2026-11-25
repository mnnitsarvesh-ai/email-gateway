import { describe, expect, it, vi } from 'vitest';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import { DLP_EXCEPTION_EXAMPLE } from '../api-docs';
import { DlpExceptionViewSchema } from '../dto/dlp.schemas';
import type { DlpConfigRepository, ExceptionRow } from '../repositories/dlp-config.repository';
import { DlpExceptionsService } from './dlp-exceptions.service';
import type { DlpAuditor } from './dlp-views';
import type { DlpWriter } from './dlp-writer';

const NOW = new Date('2026-11-24T08:00:00.000Z');
const scope = systemScope(7n);
const EXCEPTION_ID = '0190f0f0-0000-7000-8000-0000000000e7';
const POLICY_ID = '0190f0f0-0000-7000-8000-0000000000e8';
const USER_ID = '0190f0f0-0000-7000-8000-000000000003';

const row = (overrides: Partial<ExceptionRow> = {}): ExceptionRow => ({
  id: 31n,
  publicId: EXCEPTION_ID,
  organizationId: 7n,
  scope: 'recipient_domain',
  value: 'auditor.example',
  policyId: 5n,
  ruleId: null,
  policy: { publicId: POLICY_ID },
  rule: null,
  targetKey: 'p:5',
  filters: { categories: ['payment_card'] },
  reason: 'Statutory auditor',
  expiresAt: new Date('2026-11-01T00:00:00.000Z'),
  enabled: false,
  version: 3,
  createdAt: NOW,
  updatedAt: NOW,
  createdBy: { publicId: USER_ID },
  updatedBy: null,
  ...overrides,
});

function setup(found: ExceptionRow | null) {
  const repository = { findException: vi.fn(() => Promise.resolve(found)) };
  const writer = { run: vi.fn() };
  const service = new DlpExceptionsService(
    { DLP_EXCEPTIONS_MAX_PER_TENANT: 10, DLP_EXCEPTION_MAX_DAYS: 90 },
    repository as unknown as DlpConfigRepository,
    writer as unknown as DlpWriter,
    {} as DlpAuditor,
  );
  return { service, repository, writer };
}

describe('DlpExceptionsService.get (step AI-4 D8)', () => {
  it('answers the list item’s view from the replica, expired and disabled entries included', async () => {
    const { service, repository, writer } = setup(row());
    const view = await service.get(scope, EXCEPTION_ID);
    expect(DlpExceptionViewSchema.parse(view)).toEqual(view);
    expect(view).toMatchObject({
      id: EXCEPTION_ID,
      scope: 'recipient_domain',
      value: 'auditor.example',
      policyId: POLICY_ID,
      ruleId: null,
      filters: { categories: ['payment_card'] },
      expiresAt: '2026-11-01T00:00:00.000Z',
      expired: true,
      enabled: false,
      version: 3,
      createdByUserId: USER_ID,
      updatedByUserId: null,
    });
    expect(repository.findException).toHaveBeenCalledWith(scope, EXCEPTION_ID);
    expect(writer.run).not.toHaveBeenCalled();
  });

  it('answers 404 dlp_exception_not_found for an unknown id or another tenant’s id', async () => {
    const { service } = setup(null);
    const error = await service.get(scope, EXCEPTION_ID).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(CodedHttpException);
    expect((error as CodedHttpException).getStatus()).toBe(404);
    expect((error as CodedHttpException).code).toBe('dlp_exception_not_found');
  });

  it('documents an example that matches the view schema', () => {
    expect(DlpExceptionViewSchema.parse(DLP_EXCEPTION_EXAMPLE)).toEqual(DLP_EXCEPTION_EXAMPLE);
  });
});
