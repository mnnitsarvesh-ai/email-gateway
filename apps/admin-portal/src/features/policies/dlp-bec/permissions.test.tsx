import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { OperationId } from '@/lib/api/types';
import { mockApi, okJson, renderWithProviders, type SystemRoleKey } from '@/test';
import { BecTab, DlpTab } from '../dlp-bec';
import {
  compliance,
  dlpDictionaryRow,
  dlpException,
  dlpPattern,
  dlpPolicy,
  executive,
  page,
  suppression,
  trustedSender,
  vendor,
} from './test-data';

/**
 * Permission gating and first-render requests of the DLP and BEC tabs (design §2 B12, B13): the
 * API stays authoritative, the portal only hides what the session's permissions do not allow.
 * Unhandled requests fail a test (src/test/setup.ts), so each render below proves that a section
 * makes exactly its own list request on first render, and that nothing reads DLP evidence.
 */

type Section = {
  tab: 'dlp' | 'bec';
  section: string;
  op: OperationId;
  body: unknown;
  text: string;
};

const SECTIONS: readonly Section[] = [
  {
    tab: 'dlp',
    section: 'policies',
    op: 'DlpPoliciesController_list_v1',
    body: page([dlpPolicy()]),
    text: 'Payment cards outbound',
  },
  {
    tab: 'dlp',
    section: 'patterns',
    op: 'DlpPatternsController_list_v1',
    body: page([dlpPattern()]),
    text: 'Employee ID',
  },
  {
    tab: 'dlp',
    section: 'dictionaries',
    op: 'DlpDictionariesController_list_v1',
    body: page([dlpDictionaryRow()]),
    text: 'Project names',
  },
  {
    tab: 'dlp',
    section: 'exceptions',
    op: 'DlpExceptionsController_list_v1',
    body: page([dlpException()]),
    text: 'auditor.example.test',
  },
  {
    tab: 'bec',
    section: 'executives',
    op: 'BecExecutivesController_list_v1',
    body: page([executive()]),
    text: 'Dana Whitfield',
  },
  {
    tab: 'bec',
    section: 'vendors',
    op: 'BecVendorsController_list_v1',
    body: page([vendor()]),
    text: 'Bravo Logistics',
  },
  {
    tab: 'bec',
    section: 'trusted',
    op: 'BecTrustedSendersController_list_v1',
    body: page([trustedSender()]),
    text: 'partner.example.test',
  },
  {
    tab: 'bec',
    section: 'suppressions',
    op: 'BecFeedbackController_listSuppressions_v1',
    body: page([suppression()]),
    text: 'bec.content.urgency',
  },
];

const CREATE_LABELS: Record<string, string | null> = {
  policies: 'New DLP policy',
  patterns: 'New pattern',
  dictionaries: 'New dictionary',
  exceptions: 'New exception',
  executives: 'New executive',
  vendors: 'New vendor',
  trusted: 'New trusted sender',
  suppressions: null,
};

const EDIT_ITEMS: Record<string, string[]> = {
  policies: ['Rules', 'Edit', 'Delete'],
  patterns: ['Edit and test', 'Delete'],
  dictionaries: ['Edit', 'Delete'],
  exceptions: ['Edit', 'Delete'],
  executives: ['Edit', 'Delete'],
  vendors: ['Edit', 'Delete'],
  trusted: ['Edit', 'Delete'],
  suppressions: ['Lift suppression'],
};

async function renderSection(entry: Section, role: SystemRoleKey) {
  const queries: string[] = [];
  mockApi({
    [entry.op]: ({ url }: { url: URL }) => {
      queries.push(url.search);
      return okJson(entry.body as never);
    },
  });
  const Tab = entry.tab === 'dlp' ? DlpTab : BecTab;
  const view = renderWithProviders(<Tab />, {
    role,
    route: `/policies?tab=${entry.tab}&section=${entry.section}`,
  });
  await screen.findByText(entry.text);
  return { ...view, queries };
}

describe('DLP and BEC permission gating (WP5)', () => {
  it.each(SECTIONS)(
    '$tab/$section: one list request (limit 25) on first render; a security analyst gets the editing controls',
    async (entry) => {
      const { user, queries, unmount } = await renderSection(entry, 'security_analyst');
      expect(queries).toEqual(['?limit=25']);
      const create = CREATE_LABELS[entry.section];
      if (create) expect(screen.getByRole('button', { name: create })).toBeInTheDocument();
      const menu = screen.getAllByRole('button', { name: /^Actions for / })[0];
      expect(menu).toBeDefined();
      await user.click(menu as HTMLElement);
      for (const item of EDIT_ITEMS[entry.section] ?? []) {
        expect(await screen.findByRole('menuitem', { name: item })).toBeInTheDocument();
      }
      await user.keyboard('{Escape}');
      expect(queries).toHaveLength(1);
      unmount();
    },
  );

  it.each(SECTIONS)(
    '$tab/$section: a role with read but no manage permission (compliance auditor) sees no editing control',
    async (entry) => {
      const { user, unmount } = await renderSection(entry, 'compliance_auditor');
      for (const label of Object.values(CREATE_LABELS)) {
        if (label) expect(screen.queryByRole('button', { name: label })).not.toBeInTheDocument();
      }
      expect(
        screen.getByText(/View only: changing (DLP|BEC) configuration needs/),
      ).toBeInTheDocument();
      const menus = screen.queryAllByRole('button', { name: /^Actions for / });
      if (entry.section === 'policies') {
        // Read-only roles may open the rules of a policy (dlp:read), nothing else.
        await user.click(menus[0] as HTMLElement);
        const items = await screen.findAllByRole('menuitem');
        expect(items.map((item) => item.textContent)).toEqual(['Rules']);
        await user.keyboard('{Escape}');
      } else {
        expect(menus).toHaveLength(0);
      }
      unmount();
    },
  );

  it('the compliance section reads only the compliance settings; analysts get no Aadhaar controls', async () => {
    const queries: string[] = [];
    mockApi({
      DlpComplianceController_get_v1: ({ url }) => {
        queries.push(url.pathname);
        return okJson(compliance());
      },
    });
    renderWithProviders(<DlpTab />, {
      role: 'security_analyst',
      route: '/policies?tab=dlp&section=compliance',
    });
    expect(await screen.findByText('Aadhaar detection')).toBeInTheDocument();
    expect(queries).toEqual(['/bff/api/v1/dlp/compliance']);
    expect(screen.queryByRole('button', { name: /basis/i })).not.toBeInTheDocument();
  });

  it('never requests DLP evidence while moving through every DLP section', async () => {
    let evidence = 0;
    mockApi({
      DlpPoliciesController_list_v1: () => okJson(page([dlpPolicy()])),
      DlpPatternsController_list_v1: () => okJson(page([dlpPattern()])),
      DlpDictionariesController_list_v1: () => okJson(page([dlpDictionaryRow()])),
      DlpExceptionsController_list_v1: () => okJson(page([dlpException()])),
      DlpIncidentsController_list_v1: () => okJson(page([])),
      DlpComplianceController_get_v1: () => okJson(compliance()),
      DlpMessageEvidenceController_read_v1: () => ((evidence += 1), okJson({} as never)),
      DlpMessageEvidenceController_purge_v1: () => ((evidence += 1), okJson({} as never)),
      DlpEvidenceController_purgeAll_v1: () => ((evidence += 1), okJson({} as never)),
    });
    const { user } = renderWithProviders(<DlpTab />, {
      role: 'organization_admin',
      route: '/policies?tab=dlp',
    });
    await screen.findByText('Payment cards outbound');
    const sections = screen.getByRole('tablist', { name: 'DLP sections' });
    for (const [name, text] of [
      ['Patterns', 'Employee ID'],
      ['Dictionaries', 'Project names'],
      ['Exceptions', 'auditor.example.test'],
      ['Incidents', 'No DLP incidents'],
      ['Compliance', 'Aadhaar detection'],
    ] as const) {
      await user.click(within(sections).getByRole('tab', { name }));
      expect(await screen.findByText(text)).toBeInTheDocument();
    }
    expect(screen.queryByRole('button', { name: /evidence/i })).not.toBeInTheDocument();
    expect(evidence).toBe(0);
  });
});
