import { fireEvent, screen, within } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it } from 'vitest';
import { expectNoAxeViolations, expectRequestMatchesContract, renderWithProviders } from '@/test';
import { toBuilderCatalog, type BuilderCatalog } from './catalog';
import { FACT_PRESETS, setFact, type SyntheticFacts } from './facts';
import { SyntheticFactsForm } from './facts-form';
import { RAW_TEST_CATALOG, TEST_CATALOG } from './test-support/catalog';

let latest: SyntheticFacts = {};

function Harness({
  initial = {},
  catalog = TEST_CATALOG,
}: {
  initial?: SyntheticFacts;
  catalog?: BuilderCatalog;
}) {
  const [facts, setFacts] = useState<SyntheticFacts>(initial);
  latest = facts;
  return <SyntheticFactsForm catalog={catalog} value={facts} onChange={setFacts} />;
}

const OP = 'PolicyToolsController_test_v1';

describe('FACT_PRESETS (design B7)', () => {
  it('has the five presets of the design, facts data only', () => {
    expect(FACT_PRESETS.map((p) => p.id)).toEqual([
      'clean-inbound',
      'outbound-confidential',
      'phishing-url',
      'malware-attachment',
      'executable-attachment',
    ]);
    for (const preset of FACT_PRESETS) {
      expect(preset.description).not.toMatch(/quarantin|reject|allow|deliver|block/i);
    }
  });

  it.each(FACT_PRESETS.map((p) => [p.id, p.facts] as const))(
    'preset %s forms a request body that passes the OpenAPI request schema',
    (_id, facts) => {
      expectRequestMatchesContract(OP, { target: 'active', facts });
      expectRequestMatchesContract(OP, { target: 'platform', facts });
    },
  );
});

describe('setFact', () => {
  it('writes nested keys and removes emptied objects (list items stay)', () => {
    let facts: SyntheticFacts = {};
    facts = setFact(facts, ['auth', 'spf'], 'fail');
    expect(facts).toEqual({ auth: { spf: 'fail' } });
    facts = setFact(facts, ['auth', 'spf'], undefined);
    expect(facts).toEqual({});
    facts = setFact(facts, ['attachments'], [{}]);
    facts = setFact(facts, ['attachments', 0, 'verdict'], 'clean');
    expect(facts).toEqual({ attachments: [{ verdict: 'clean' }] });
    facts = setFact(facts, ['attachments', 0, 'verdict'], undefined);
    expect(facts).toEqual({ attachments: [{}] });
    expect(setFact({ risk: { rev0: { score: 1 } } }, ['risk'], null)).toEqual({ risk: null });
  });
});

/** Interaction-heavy tests get a margin for a loaded parallel run (alone each takes a few seconds). */
const SLOW = 60_000;

function setup(initial?: SyntheticFacts) {
  const result = renderWithProviders(<Harness initial={initial} />);
  const select = async (name: string, option: string, scope: HTMLElement = document.body) => {
    await result.user.click(within(scope).getByRole('combobox', { name }));
    await result.user.click(await screen.findByRole('option', { name: option }));
  };
  return { ...result, select };
}

describe('SyntheticFactsForm', () => {
  it('passes axe with every section', async () => {
    const { container } = renderWithProviders(<Harness initial={FACT_PRESETS[2]!.facts} />);
    await expectNoAxeViolations(container);
  });

  it(
    'message, sender, recipient, connection and authentication facts (catalogue vocabularies; only keys set)',
    async () => {
      const { user, select } = setup();
      await select('Direction', 'Outbound');
      await select('Scan outcome', 'Not scanned');
      fireEvent.change(screen.getByLabelText('Evaluation time (UTC)'), {
        target: { value: '2026-03-09T23:30' },
      });
      await user.type(screen.getByRole('spinbutton', { name: 'Message size' }), '2');
      await select('Unit', 'MiB');
      await user.type(
        screen.getByRole('textbox', { name: 'Envelope sender address' }),
        'trader@corp.example',
      );
      await select('Sender authenticated', 'Yes');
      await user.type(
        screen.getByRole('textbox', { name: 'Add recipient' }),
        'a@customer.example, b@customer.example{Enter}',
      );
      await user.click(
        screen.getByRole('checkbox', { name: /Resolve department and user memberships/ }),
      );
      await user.type(screen.getByRole('textbox', { name: 'Client IP address' }), '198.51.100.25');
      await select('SPF result', 'Fail');
      await select('DMARC result', 'None');
      expect(latest).toEqual({
        direction: 'outbound',
        trigger: 'parse_failed',
        evaluationTime: '2026-03-09T23:30:00.000Z',
        message: { sizeBytes: 2 * 1024 * 1024 },
        sender: { envelope: 'trader@corp.example', authenticated: true },
        recipients: [{ address: 'a@customer.example' }, { address: 'b@customer.example' }],
        resolveDirectory: true,
        client: { ip: '198.51.100.25' },
        auth: { spf: 'fail', dmarc: 'none' },
      });
      expectRequestMatchesContract(OP, { target: 'active', facts: latest });
      // Clearing removes the keys again (no empty object left behind).
      await select('SPF result', 'Not set (default)');
      await select('DMARC result', 'Not set (default)');
      expect('auth' in latest).toBe(false);
    },
    SLOW,
  );

  it(
    'attachment and link lists',
    async () => {
      const { user, select } = setup();
      await user.click(screen.getByRole('button', { name: 'Add attachment' }));
      const attachment = screen.getByRole('group', { name: 'Attachment 1' });
      await user.type(
        within(attachment).getByRole('textbox', { name: 'Attachment file name' }),
        'setup.exe',
      );
      await select('Attachment type family', 'Executable', attachment);
      await select('Attachment verdict', 'Clean', attachment);
      await user.type(
        within(attachment).getByRole('combobox', { name: 'Add code' }),
        'attachment.malware{Enter}',
      );
      await user.click(screen.getByRole('button', { name: 'Add link' }));
      const link = screen.getByRole('group', { name: 'Link 1' });
      await user.type(
        within(link).getByRole('textbox', { name: 'Link host (required)' }),
        'login.account-verify.example',
      );
      await select('Link verdict', 'Malicious', link);
      await select('Link rewriting', 'Skipped');
      expect(latest).toEqual({
        attachments: [
          {
            filename: 'setup.exe',
            typeFamily: 'executable',
            verdict: 'clean',
            reasonCodes: ['attachment.malware'],
          },
        ],
        urls: [{ host: 'login.account-verify.example', verdict: 'malicious' }],
        urlRewriteStatus: 'skipped',
      });
      expectRequestMatchesContract(OP, { target: 'active', facts: latest });
      await user.click(within(attachment).getByRole('button', { name: 'Remove attachment 1' }));
      expect('attachments' in latest).toBe(false);
    },
    SLOW,
  );

  it(
    'risk revision 0 with hard blocks, and a missing risk row',
    async () => {
      const { user, select } = setup();
      await user.type(screen.getByRole('spinbutton', { name: 'Risk score' }), '900');
      await select('Risk level', 'Critical');
      await select('Risk verdict', 'Phishing');
      await select('Recommended action', 'Quarantine');
      await user.click(screen.getByRole('checkbox', { name: 'hb.known_phishing' }));
      await select('Action of hb.known_phishing', 'Quarantine');
      expect(latest).toEqual({
        risk: {
          rev0: {
            score: 900,
            level: 'critical',
            verdict: 'phishing',
            recommendedAction: 'quarantine',
            hardBlocks: [{ id: 'hb.known_phishing', action: 'quarantine' }],
          },
        },
      });
      expectRequestMatchesContract(OP, { target: 'active', facts: latest });
      await user.click(
        screen.getByRole('checkbox', { name: 'No risk result (a missing risk row)' }),
      );
      expect(latest).toEqual({ risk: null });
      expect(screen.queryByRole('spinbutton', { name: 'Risk score' })).not.toBeInTheDocument();
      expectRequestMatchesContract(OP, { target: 'active', facts: latest });
    },
    SLOW,
  );

  it(
    'DLP, BEC and scan results (the required key first); clearing removes the result',
    async () => {
      const { user, select } = setup();
      expect(screen.queryByRole('combobox', { name: 'DLP verdict' })).not.toBeInTheDocument();
      await select('DLP action', 'Alert');
      await user.click(screen.getByRole('checkbox', { name: 'Confidential' }));
      await select('Highest DLP severity', 'High');
      await select('BEC verdict (deterministic)', 'Suspicious');
      await select('Raised by the AI layer', 'Yes');
      await select('Scan verdict', 'Suspicious');
      expect(latest).toEqual({
        dlp: { action: 'alert', categories: ['confidential'], maxSeverity: 'high' },
        bec: { deterministicVerdict: 'suspicious', aiRaised: true },
        scan: { verdict: 'suspicious' },
      });
      expectRequestMatchesContract(OP, { target: 'active', facts: latest });
      await select('DLP action', 'No DLP result');
      await select('BEC verdict (deterministic)', 'No BEC result');
      expect(latest).toEqual({ scan: { verdict: 'suspicious' } });
    },
    SLOW,
  );

  it('shows a preset (controlled value) in its inputs', () => {
    const preset = FACT_PRESETS.find((p) => p.id === 'phishing-url')!;
    renderWithProviders(<Harness initial={preset.facts} />);
    expect(screen.getByRole('combobox', { name: 'SPF result' })).toHaveTextContent('Fail');
    expect(screen.getByRole('textbox', { name: 'Link host (required)' })).toHaveValue(
      'login.account-verify.example',
    );
    expect(screen.getByRole('checkbox', { name: 'hb.known_phishing' })).toBeChecked();
  });

  it('hides sections whose catalogue fields are missing', () => {
    const catalog = toBuilderCatalog({
      ...RAW_TEST_CATALOG,
      fields: RAW_TEST_CATALOG.fields.filter(
        (f) => !f.name.startsWith('auth.') && !f.name.startsWith('dlp.'),
      ),
    });
    renderWithProviders(<Harness catalog={catalog} />);
    expect(screen.queryByRole('group', { name: 'Authentication' })).not.toBeInTheDocument();
    expect(screen.queryByRole('group', { name: 'Data loss prevention' })).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Message' })).toBeInTheDocument();
  });
});
