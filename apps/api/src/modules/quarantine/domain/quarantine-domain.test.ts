import {
  quarantineApprovalViewSchema,
  quarantineEntryDetailSchema,
  quarantineEntrySummarySchema,
  quarantineReleaseViewSchema,
} from '@email-gateway/quarantine';
import { describe, expect, it } from 'vitest';
import { QuarantineWorld } from '../../../../test/support/in-memory-quarantine';
import { quarantineRate } from '../quarantine-rate-limit';
import { downloadFilename } from '../services/quarantine-download.service';
import { archiveRequested } from '../services/quarantine-disposition.service';
import { bulkItemKey, itemFailure } from '../services/quarantine-bulk.service';
import { plannedBody } from '../services/quarantine-preview.service';
import { levelsFrom } from '../services/quarantine-query.service';
import { changedPaths } from '../services/quarantine-settings.service';
import { entryNotFound, stateConflict } from '../quarantine.errors';
import {
  IDEMPOTENCY_KEY_MAX_LENGTH,
  IDEMPOTENCY_KEY_PATTERN,
} from '../../../http/idempotency/idempotency-key';
import {
  approvalView,
  entryDetail,
  entrySummary,
  hardBlockIds,
  releaseView,
  revalidationSummary,
  stringList,
  uuidOrNull,
} from './entry';

const world = new QuarantineWorld();
const refs = {
  messagePublicId: '0190a5b2-7c3d-7e4f-8a1b-000000000abc',
  approvalPublicId: null,
  subject: null,
};

describe('entry views (Q26 DTOs)', () => {
  it('summary and detail parse with the shared strict schemas; subject sanitized', () => {
    const row = world.addEntry({
      hardBlocks: ['hb.malware.attachment'],
      explanation: [{ code: 'summary', params: { disposition: 'quarantine' } }],
    });
    const summary = entrySummary(row, { ...refs, subject: 'Pay‮ now\u0007' });
    expect(quarantineEntrySummarySchema.parse(summary)).toEqual(summary);
    expect(summary.subject).toBe('Pay now');
    const detail = entryDetail(row, refs, [], ['preview']);
    expect(quarantineEntryDetailSchema.parse(detail)).toEqual(detail);
    expect(detail.explanation.lines).toHaveLength(1);
    // A malformed stored explanation shows no lines (never throws).
    expect(entryDetail({ ...row, explanation: 'broken' }, refs, [], []).explanation.lines).toEqual(
      [],
    );
  });

  it('release and approval views', () => {
    const release = releaseView({
      id: 1n,
      quarantineMessageId: 1n,
      entryPublicId: refs.messagePublicId,
      releasePublicId: refs.messagePublicId,
      mode: 'operator',
      status: 'pending',
      requestedByType: 'user',
      requestedById: 'not-a-uuid',
      revalidation: { summary: { bad: true } },
      deliveredObject: null,
      approvalRequestPublicId: null,
      createdAt: new Date(),
      completedAt: null,
    });
    expect(quarantineReleaseViewSchema.parse(release)).toEqual(release);
    expect(release.requestedBy.id).toBeNull();
    expect(release.revalidation).toBeNull();
    const approval = approvalView({
      id: 1n,
      publicId: refs.messagePublicId,
      organizationId: 1n,
      quarantineMessageId: 1n,
      entryPublicId: refs.messagePublicId,
      kind: 'release_request',
      status: 'pending',
      approvalReasons: ['review'],
      approvedReasons: null,
      requestedByType: 'system',
      requestedByUserId: null,
      requestedByApiKeyId: null,
      requestedByPublicId: null,
      requestReason: 'x',
      decidedByUserId: null,
      decidedByPublicId: null,
      decisionReason: null,
      expiresAt: new Date(),
      decidedAt: null,
      rowVersion: 1,
      createdAt: new Date(),
    });
    expect(quarantineApprovalViewSchema.parse(approval)).toEqual(approval);
    expect(revalidationSummary(null)).toBeNull();
    expect(stringList(['a', 1, null, 'b'])).toEqual(['a', 'b']);
    expect(uuidOrNull(null)).toBeNull();
  });

  it('hardBlockIds reads the step 5.1 risk-row objects and plain ids (WP5 regression)', () => {
    // message_risk_scores.hard_blocks holds `{ id, action, verdict }` objects: stringList dropped
    // them, so manual-quarantine entries lost their hard blocks and the download gate its
    // message-level hard blocks.
    expect(
      hardBlockIds([
        { id: 'hb.malware_attachment', action: 'block', verdict: 'malware' },
        'hb.known_phishing',
        { action: 'block' },
        null,
        7,
      ]),
    ).toEqual(['hb.malware_attachment', 'hb.known_phishing']);
    expect(hardBlockIds(null)).toEqual([]);
    expect(hardBlockIds([{ id: 'a' }, { id: 'b' }, { id: 'c' }], 2)).toEqual(['a', 'b']);
  });
});

describe('helpers', () => {
  it('levelsFrom (minRiskLevel)', () => {
    expect(levelsFrom('high')).toEqual(['high', 'critical']);
    expect(levelsFrom('none')).toHaveLength(5);
  });

  it('downloadFilename: ASCII, no quotes or paths, the .eml.bin / .bin suffix', () => {
    expect(downloadFilename('../../etc/"pass wd".exe', 'attachment')).toBe('etc_pass_wd_.exe.bin');
    expect(downloadFilename(null, 'eml')).toBe('message.eml.bin');
    expect(downloadFilename('Rechnung März.pdf', 'attachment')).toMatch(
      /^Rechnung_Ma.*rz\.pdf\.bin$/,
    );
    expect(downloadFilename('a'.repeat(300), 'attachment').length).toBeLessThanOrEqual(104);
  });

  it('archiveRequested reads stored ARCHIVE actions', () => {
    expect(archiveRequested([{ type: 'ARCHIVE', status: 'requested' }])).toBe(true);
    expect(archiveRequested([{ type: 'ARCHIVE', status: 'recorded' }, null, 'x'])).toBe(false);
  });

  it('bulk item keys are valid Idempotency-Keys; failures map to per-item results', () => {
    const key = bulkItemKey('k'.repeat(128), '0190a5b2-7c3d-7e4f-8a1b-000000000abc');
    expect(key.length).toBeLessThanOrEqual(IDEMPOTENCY_KEY_MAX_LENGTH);
    expect(IDEMPOTENCY_KEY_PATTERN.test(key)).toBe(true);
    expect(itemFailure('i', entryNotFound())).toEqual({
      id: 'i',
      status: 'not_found',
      code: 'quarantine_entry_not_found',
    });
    expect(itemFailure('i', stateConflict('held'))).toEqual({
      id: 'i',
      status: 'refused',
      code: 'quarantine_state_conflict',
    });
    expect(itemFailure('i', new Error('boom'))).toBeNull();
  });

  it('plannedBody: purged, not parsed, text before html, no text part', () => {
    const live = { objectPurgedAt: null };
    expect(plannedBody({ objectPurgedAt: new Date() }, null)).toEqual({
      source: null,
      unavailable: 'purged',
    });
    expect(plannedBody(live, null)).toEqual({ source: null, unavailable: 'not_parsed' });
    expect(plannedBody(live, { status: 'failed', textKey: 'a', htmlKey: null })).toEqual({
      source: null,
      unavailable: 'not_parsed',
    });
    expect(plannedBody(live, { status: 'parsed', textKey: 't', htmlKey: 'h' })).toEqual({
      source: 'text',
      key: 't',
    });
    expect(plannedBody(live, { status: 'parsed', textKey: null, htmlKey: 'h' })).toEqual({
      source: 'html',
      key: 'h',
    });
    expect(plannedBody(live, { status: 'parsed', textKey: null, htmlKey: null })).toEqual({
      source: null,
      unavailable: 'no_text_part',
    });
  });

  it('changedPaths lists the changed leaves only', () => {
    expect(changedPaths({}, { endUser: { selfRelease: true } })).toEqual(['endUser.selfRelease']);
    expect(changedPaths({ a: { b: 1, c: 2 } }, { a: { b: 1 } })).toEqual(['a.c']);
    expect(changedPaths({ a: [1] }, { a: [1] })).toEqual([]);
  });

  it('quarantineRate reads the env-configured limits', () => {
    const cfg = {
      QUARANTINE_PREVIEW_RATE_PER_MINUTE: 7,
      QUARANTINE_DOWNLOAD_GRANTS_PER_HOUR: 5,
      QUARANTINE_BULK_REQUESTS_PER_MINUTE: 3,
    };
    expect(quarantineRate('preview', cfg)).toEqual({
      bucket: 'quarantine-preview',
      limit: 7,
      windowSeconds: 60,
    });
    expect(quarantineRate('download_grant', cfg)).toMatchObject({ limit: 5, windowSeconds: 3600 });
    expect(quarantineRate('download', cfg)).toMatchObject({ limit: 5, windowSeconds: 3600 });
    expect(quarantineRate('bulk', cfg)).toMatchObject({ limit: 3, windowSeconds: 60 });
  });
});
