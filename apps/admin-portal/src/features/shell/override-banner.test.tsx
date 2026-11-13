import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';
import {
  TEST_ORIGIN,
  makeMe,
  makeSession,
  mockApi,
  okJson,
  renderWithProviders,
  server,
} from '@/test';
import { useSession } from '@/lib/auth/me';
import { OverrideBanner } from './override-banner';

/** The shell's pattern: the banner is shown while the cached session has an override. */
function ShellLike() {
  const session = useSession();
  const override = session.data?.override;
  return override ? (
    <OverrideBanner
      organizationName={override.organizationName}
      operator="Operator"
      expiresAt={override.expiresAt}
      reason="Investigating a reported phishing campaign"
    />
  ) : (
    <p>No override</p>
  );
}

describe('OverrideBanner', () => {
  it('"End now" ends the override and the mounted session query drops the banner', async () => {
    const active = makeSession({
      override: {
        id: '5a0c7f8e-8f53-4b55-9a52-6b3b8d1c2e11',
        organizationId: '01a1d455-0c99-76c3-a4c7-2fcc7b045e9f',
        organizationName: 'Beta Corp',
        expiresAt: new Date(Date.now() + 600_000).toISOString(),
      },
    });
    let ended = false;
    server.use(
      http.delete(`${TEST_ORIGIN}/bff/session/override`, () => {
        ended = true;
        return new HttpResponse(null, { status: 204 });
      }),
      http.get(`${TEST_ORIGIN}/bff/session`, () =>
        HttpResponse.json(ended ? makeSession() : active),
      ),
    );
    mockApi({ AuthController_me_v1: () => okJson(makeMe() as never) });
    const { user } = renderWithProviders(<ShellLike />, { session: active });
    const banner = await screen.findByRole('region', { name: 'Tenant override' });
    expect(banner).toHaveTextContent('Acting in Beta Corp as Operator');
    await user.click(screen.getByRole('button', { name: 'End now' }));
    await waitFor(() =>
      expect(screen.queryByRole('region', { name: 'Tenant override' })).toBeNull(),
    );
    expect(screen.getByText('No override')).toBeInTheDocument();
    expect(ended).toBe(true);
  });
});
