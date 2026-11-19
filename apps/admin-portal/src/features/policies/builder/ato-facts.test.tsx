import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { screen, within } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, expectRequestMatchesContract, renderWithProviders } from '@/test';
import { REAL_BUILDER_CATALOG, REAL_CATALOG } from '../test-data';
import { type BuilderCatalog } from './catalog';
import {
  ATO_HIGH_RISK_PRESET_ID,
  FACT_PRESETS,
  factPresetById,
  type SyntheticFacts,
} from './facts';
import {
  ACCOUNT_TAKEOVER_GROUP,
  SyntheticFactsForm,
  accountTakeoverFactFields,
  factKeyOfField,
  initialAccountTakeoverFacts,
} from './facts-form';
import { TEST_CATALOG } from './test-support/catalog';

/**
 * Step 8.4 D23 in the builder: the account takeover fields reach the portal only through the
 * catalogue (group `account_takeover`); the synthetic-facts form renders an "Account takeover"
 * section from their labels and vocabularies; the preset "Outbound from a high-risk account".
 */

const OP = 'PolicyToolsController_test_v1';
let latest: SyntheticFacts = {};

function Harness({ catalog, initial = {} }: { catalog: BuilderCatalog; initial?: SyntheticFacts }) {
  const [facts, setFacts] = useState<SyntheticFacts>(initial);
  latest = facts;
  return <SyntheticFactsForm catalog={catalog} value={facts} onChange={setFacts} />;
}

const ATO_FIELDS = REAL_CATALOG.fields.filter((f) => f.group === ACCOUNT_TAKEOVER_GROUP);

describe('account takeover fields come from the catalogue only (ADR-0063)', () => {
  it('the real catalogue has the account takeover group with its fields', () => {
    expect(REAL_CATALOG.fieldGroups.map((g) => g.id)).toContain(ACCOUNT_TAKEOVER_GROUP);
    expect(ATO_FIELDS.length).toBeGreaterThanOrEqual(4);
    for (const field of ATO_FIELDS) {
      // Offered only where they make a decision stricter (strictOnly, D23).
      expect(field.contexts.exception, field.name).toBe(false);
      expect(field.contexts.relaxingWhen, field.name).toBe(false);
      expect(field.contexts.holdRule, field.name).toBe(true);
    }
  });

  it('no portal source file names an account takeover DSL field', () => {
    const root = join(__dirname, '../../../..');
    const src = join(root, 'src');
    // Generated or verbatim copies of the api snapshot are allowed to contain them.
    const allowed = new Set([
      'src/lib/api/schema.gen.ts',
      'src/server/dev-mocks/fixtures/policy-catalog.data.ts',
    ]);
    const names = ATO_FIELDS.map((f) => f.name);
    const hits: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        if (entry === 'node_modules' || entry === 'dist' || entry.startsWith('.')) continue;
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full);
        else if (/\.(ts|tsx|mjs|js)$/.test(entry)) {
          const rel = relative(root, full).split('\\').join('/');
          if (allowed.has(rel)) continue;
          const text = readFileSync(full, 'utf8');
          for (const name of names) if (text.includes(name)) hits.push(`${rel}: ${name}`);
        }
      }
    };
    walk(src);
    walk(join(root, '../../tests/portal-e2e'));
    expect(hits).toEqual([]);
  });

  it('maps catalogue field names to synthetic facts keys generically', () => {
    expect(factKeyOfField('group.some_long_name')).toEqual({ root: 'group', key: 'someLongName' });
    expect(factKeyOfField('nodot')).toBeNull();
    const mapped = accountTakeoverFactFields(REAL_BUILDER_CATALOG).map((f) => f.key);
    expect(mapped).toEqual(
      expect.arrayContaining(['riskScore', 'riskLevel', 'incidentSeverity', 'incidentStatus']),
    );
    const initial = initialAccountTakeoverFacts(REAL_BUILDER_CATALOG);
    expect(Object.keys(initial).sort()).toEqual(['riskLevel', 'riskScore']);
  });
});

describe('the "Account takeover" synthetic facts section', () => {
  it('is hidden when the catalogue has no account takeover fields', () => {
    renderWithProviders(<Harness catalog={TEST_CATALOG} />);
    expect(screen.queryByRole('group', { name: 'Account takeover' })).not.toBeInTheDocument();
  });

  it('adds the block with the required keys, edits every field and passes the contract', async () => {
    const { user, container } = renderWithProviders(<Harness catalog={REAL_BUILDER_CATALOG} />);
    const section = screen.getByRole('group', { name: 'Account takeover' });
    const select = async (name: string, option: string) => {
      await user.click(within(section).getByRole('combobox', { name }));
      await user.click(await screen.findByRole('option', { name: option }));
    };
    await select('Sender account facts', 'Set account takeover facts');
    expect(latest).toEqual({ ato: initialAccountTakeoverFacts(REAL_BUILDER_CATALOG) });

    const labels = Object.fromEntries(
      accountTakeoverFactFields(REAL_BUILDER_CATALOG).map(({ field, key }) => [key, field.label]),
    );
    await select(labels.riskLevel!, 'High');
    const score = within(section).getByRole('spinbutton', { name: labels.riskScore });
    await user.clear(score);
    await user.type(score, '72');
    await select(labels.incidentSeverity!, 'Critical');
    await select(labels.incidentStatus!, 'Investigating');
    await select('Account known (monitored)', 'No');
    expect(latest).toEqual({
      ato: {
        riskScore: 72,
        riskLevel: 'high',
        incidentSeverity: 'critical',
        incidentStatus: 'investigating',
        accountKnown: false,
      },
    });
    expectRequestMatchesContract(OP, { target: 'active', facts: latest });
    // The optional incident facts can be cleared again; the required ones offer no "unset".
    await select(labels.incidentSeverity!, 'None (no active incident)');
    expect(latest.ato && 'incidentSeverity' in latest.ato).toBe(false);
    await user.click(within(section).getByRole('combobox', { name: labels.riskLevel }));
    expect(screen.queryByRole('option', { name: /None|Not set/ })).not.toBeInTheDocument();
    await user.keyboard('{Escape}');
    await expectNoAxeViolations(container);
    // Removing the block removes every key.
    await select('Sender account facts', 'None (fields are unknown)');
    expect(latest).toEqual({});
  }, 60_000);
});

describe('preset "Outbound from a high-risk account"', () => {
  it('is an outbound example with a high account risk and a valid request body', () => {
    const preset = factPresetById(ATO_HIGH_RISK_PRESET_ID);
    expect(preset?.label).toBe('Outbound from a high-risk account');
    expect(preset?.facts.direction).toBe('outbound');
    expect(preset?.facts.ato).toEqual({ riskScore: 65, riskLevel: 'high' });
    expectRequestMatchesContract(OP, { target: 'active', facts: preset!.facts });
    expect(FACT_PRESETS.at(-1)?.id).toBe(ATO_HIGH_RISK_PRESET_ID);
    expect(factPresetById('unknown')).toBeNull();
  });

  it('renders in the form with the account takeover section filled', () => {
    renderWithProviders(
      <Harness
        catalog={REAL_BUILDER_CATALOG}
        initial={factPresetById(ATO_HIGH_RISK_PRESET_ID)!.facts}
      />,
    );
    const section = screen.getByRole('group', { name: 'Account takeover' });
    const level = accountTakeoverFactFields(REAL_BUILDER_CATALOG).find(
      (f) => f.key === 'riskLevel',
    )!.field.label;
    expect(within(section).getByRole('combobox', { name: level })).toHaveTextContent('High');
  });
});
