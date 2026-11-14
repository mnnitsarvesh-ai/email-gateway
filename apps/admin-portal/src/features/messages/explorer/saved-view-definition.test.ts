import { describe, expect, it } from 'vitest';
import { expectRequestMatchesContract, validateRequestBody } from '@/test';
import { EXPLORER_COLUMN_IDS, columnsOfVisibility, visibilityOfColumns } from './columns';
import { DEFAULT_EXPLORER_STATE, type ExplorerState } from './explorer-state';
import {
  applyDefinition,
  createSavedViewSchema,
  createViewBody,
  definitionFromState,
  definitionKey,
  updateViewBody,
  viewNameFormSchema,
} from './saved-view-definition';
import { savedView } from './test-helpers';

const NOW = Date.parse('2026-11-14T10:20:30.000Z');
const state = (patch: Partial<ExplorerState> = {}): ExplorerState => ({
  ...DEFAULT_EXPLORER_STATE,
  ...patch,
});
const all = () => true;

describe('saved view definitions (§2 E4, §3.3)', () => {
  it('builds the definition of the current state: api parameters, relative range, sort, columns', () => {
    const definition = definitionFromState(
      state({
        range: '7d',
        verdict: ['phishing', 'malware'],
        messageId: '<abc@mail.example.test>',
        riskMin: 600,
        sort: 'receivedAt',
      }),
      ['receivedAt', 'subject', 'verdict'],
    );
    expect(definition).toEqual({
      version: 1,
      filters: {
        verdict: 'phishing,malware',
        'riskScore.gte': '600',
        internetMessageId: '<abc@mail.example.test>',
      },
      sort: 'receivedAt',
      range: { kind: 'relative', preset: '7d' },
      columns: ['receivedAt', 'subject', 'verdict'],
    });
  });

  it('a custom range becomes an absolute range', () => {
    const definition = definitionFromState(
      state({ range: 'custom', from: '2026-11-01T08:00:00.000Z', to: '2026-11-02T08:00:00.000Z' }),
      null,
    );
    expect(definition.range).toEqual({
      kind: 'absolute',
      from: '2026-11-01T08:00:00.000Z',
      to: '2026-11-02T08:00:00.000Z',
    });
  });

  it('create and update bodies match the OpenAPI request schemas (strict)', () => {
    const definition = definitionFromState(
      state({
        range: 'custom',
        from: '2026-11-01T08:00:00.000Z',
        to: '2026-11-02T08:00:00.000Z',
        direction: ['inbound'],
        senderDomain: 'xn--mnchen-3ya.example.test',
        quarantineStatus: 'held',
      }),
      ['receivedAt', 'from', 'subject'],
    );
    expectRequestMatchesContract(
      'SavedViewsController_create_v1',
      createViewBody('Held from München', definition),
    );
    expectRequestMatchesContract(
      'SavedViewsController_update_v1',
      updateViewBody({ rowVersion: 4 }, 'Renamed', definitionFromState(state(), null)),
    );
    // The contract helper fails on unknown keys: the strict schema refuses them first.
    expect(validateRequestBody('SavedViewsController_create_v1', { kind: 'x' })).not.toEqual([]);
    expect(() =>
      createSavedViewSchema.parse({
        kind: 'message_explorer',
        name: 'x',
        definition: { ...definition, extra: true },
      }),
    ).toThrow();
  });

  it('view names are trimmed, 1–80 characters, without control characters', () => {
    expect(viewNameFormSchema.parse({ name: '  Phishing  ' }).name).toBe('Phishing');
    expect(viewNameFormSchema.safeParse({ name: '   ' }).success).toBe(false);
    expect(viewNameFormSchema.safeParse({ name: 'x'.repeat(81) }).success).toBe(false);
    expect(viewNameFormSchema.safeParse({ name: `a${String.fromCharCode(7)}b` }).success).toBe(
      false,
    );
  });

  it('applies a view: every filter key cleared or set, range, sort, view id, columns', () => {
    const applied = applyDefinition(
      savedView({
        definition: {
          version: 1,
          filters: {
            direction: 'inbound',
            verdict: 'phishing,malware',
            internetMessageId: '<abc@mail.example.test>',
            'riskScore.lte': '400',
            hasAttachments: 'false',
          },
          sort: 'receivedAt',
          range: { kind: 'relative', preset: '30d' },
          columns: ['receivedAt', 'subject', 'risk'],
        },
      }),
      all,
      EXPLORER_COLUMN_IDS,
      NOW,
    );
    expect(applied.skipped).toEqual([]);
    expect(applied.patch).toMatchObject({
      direction: ['inbound'],
      verdict: ['phishing', 'malware'],
      status: [],
      sender: undefined,
      messageId: '<abc@mail.example.test>',
      riskMax: 400,
      riskMin: undefined,
      attachments: 'false',
      hasAttachments: undefined,
      range: '30d',
      from: undefined,
      to: undefined,
      sort: 'receivedAt',
      view: savedView().id,
    });
    expect(applied.columns).toEqual(['receivedAt', 'subject', 'risk']);
  });

  it('an outdated view applies what it can and lists the rest', () => {
    const applied = applyDefinition(
      savedView({
        definition: {
          version: 1,
          filters: {
            'riskScore.gt': '700',
            status: 'quarantined,teleported',
            subject: 'Invoice',
            senderDomain: 'example.com',
          },
          sort: '-receivedAt',
          range: {
            kind: 'absolute',
            from: '2026-01-01T00:00:00.000Z',
            to: '2026-03-01T00:00:00.000Z',
          },
          columns: ['receivedAt', 'legacyScore'],
        },
      }),
      (permission) => permission !== 'message:reveal',
      EXPLORER_COLUMN_IDS,
      NOW,
    );
    expect(applied.patch).toMatchObject({
      senderDomain: 'example.com',
      range: '24h',
      subject: undefined,
    });
    expect(applied.columns).toEqual(['receivedAt']);
    expect(applied.skipped).toEqual([
      'the filter riskScore.gt (not offered by the explorer)',
      'the filter status (its value is no longer valid)',
      'the filter Subject (needs message:reveal)',
      'its time range (replaced by the last 24 hours)',
      'the columns legacyScore',
    ]);
  });

  it('an absolute range within 31 days is applied as a custom range', () => {
    const applied = applyDefinition(
      savedView({
        definition: {
          ...savedView().definition,
          range: {
            kind: 'absolute',
            from: '2026-11-01T08:00:00.000Z',
            to: '2026-11-03T08:00:00.000Z',
          },
        },
      }),
      all,
      EXPLORER_COLUMN_IDS,
      NOW,
    );
    expect(applied.patch).toMatchObject({
      range: 'custom',
      from: '2026-11-01T08:00:00.000Z',
      to: '2026-11-03T08:00:00.000Z',
    });
  });

  it('compares definitions regardless of filter and column order', () => {
    const a = savedView().definition;
    const b = { ...a, filters: { verdict: 'phishing', direction: 'inbound' } };
    expect(definitionKey(a)).toBe(definitionKey(b));
    expect(definitionKey(a)).not.toBe(definitionKey({ ...a, sort: 'receivedAt' }));
  });
});

describe('column sets', () => {
  it('a full column set is saved as null (the default) and restored as all visible', () => {
    expect(columnsOfVisibility({})).toBeNull();
    expect(visibilityOfColumns(null)).toEqual({});
  });

  it('a partial set round-trips; the received column cannot be hidden', () => {
    const visibility = visibilityOfColumns(['subject', 'risk']);
    expect(visibility.receivedAt).toBe(true);
    expect(visibility.size).toBe(false);
    expect(columnsOfVisibility(visibility)).toEqual(['receivedAt', 'subject', 'risk']);
  });
});
