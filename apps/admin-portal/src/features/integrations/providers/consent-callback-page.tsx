'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { PageHeader } from '@/components/page-header';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { MutationError, Section } from '@/features/domains/kit';
import { CONNECTION_QUERIES } from './mail-flow-dialog';
import { errorHint } from './model';
import { scrubQueryString } from './navigate';

type ConsentBody = RequestBody<'ProviderGrantsController_completeConsent_v1'>;

const STATE = /^[A-Za-z0-9_-]{43}$/;

/**
 * Builds the JSON body of `POST /provider-connections/consent/complete` from Microsoft's redirect
 * parameters (D3.2). `null` when the redirect carries no usable state. The tenant is only a claim
 * (the worker verifies it); bounded lengths follow the api schema.
 */
export function consentBodyFrom(params: URLSearchParams): ConsentBody | null {
  const state = params.get('state') ?? '';
  if (!STATE.test(state)) return null;
  const tenant = params.get('tenant');
  const adminConsent = params.get('admin_consent');
  const error = params.get('error');
  const description = params.get('error_description');
  return {
    state,
    ...(tenant ? { tenant: tenant.slice(0, 64) } : {}),
    ...(adminConsent !== null ? { adminConsent: adminConsent.toLowerCase() === 'true' } : {}),
    ...(error ? { error: error.slice(0, 128) } : {}),
    ...(description ? { errorDescription: description.slice(0, 2048) } : {}),
  };
}

function Callback({ body }: { body: ConsentBody | null }) {
  const router = useRouter();
  const [declined, setDeclined] = useState<string | null>(null);
  const posted = useRef(false);
  const complete = useApiMutation('ProviderGrantsController_completeConsent_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: null,
  });

  const finish = (outcome: Awaited<ReturnType<typeof complete.submit>>) => {
    if (!outcome.ok) return;
    if (body?.error || outcome.data.status === 'error') {
      setDeclined(outcome.data.connectionId);
      return;
    }
    router.replace(`/integrations/providers/${outcome.data.connectionId}?tab=setup`);
  };

  useEffect(() => {
    if (!body || posted.current) return;
    posted.current = true;
    void complete.submit({ body }).then(finish);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- exactly one completion per page load
  }, []);

  if (!body) {
    return (
      <Section title="This consent link cannot be used">
        <p className="text-sm">
          The page was opened without a valid consent response. Start the consent again from the
          connection’s Setup tab.
        </p>
        <Button asChild variant="outline" className="justify-self-start">
          <Link href="/integrations">Back to integrations</Link>
        </Button>
      </Section>
    );
  }

  if (declined) {
    return (
      <Section title="Consent was not granted">
        <p className="text-sm">
          Microsoft reported that the consent was declined or failed. Nothing was connected. You can
          start the consent again from the connection.
        </p>
        <Button asChild className="justify-self-start">
          <Link href={`/integrations/providers/${declined}?tab=setup`}>Back to the connection</Link>
        </Button>
      </Section>
    );
  }

  if (complete.error) {
    const permanent = complete.error.status >= 400 && complete.error.status < 500;
    return (
      <Section title="The consent could not be completed">
        <MutationError error={complete.error} />
        {errorHint(complete.error.code) ? (
          <p className="text-sm">{errorHint(complete.error.code)}</p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          {!permanent || complete.error.status === 429 ? (
            <Button
              disabled={complete.isPending || complete.retryAfterSeconds > 0}
              onClick={() => void complete.retry().then(finish)}
            >
              {complete.retryAfterSeconds > 0
                ? `Try again in ${complete.retryAfterSeconds} s`
                : 'Try again'}
            </Button>
          ) : null}
          <Button asChild variant="outline">
            <Link href="/integrations">Back to integrations</Link>
          </Button>
        </div>
      </Section>
    );
  }

  return <LoadingState label="Completing the Microsoft 365 consent" rows={2} />;
}

/** `/integrations/providers/consent-callback`: Microsoft's admin-consent redirect target (D3). */
export function ConsentCallbackPage() {
  const params = useSearchParams();
  // Captured once, then the query string (it carries the single-use state) is scrubbed from the
  // address bar and history before anything else runs; the values travel only in a JSON body.
  const [body] = useState<ConsentBody | null>(() => consentBodyFrom(new URLSearchParams(params)));
  // A layout effect runs before every passive effect, so before the completion request starts.
  useLayoutEffect(() => {
    scrubQueryString();
  }, []);
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader title="Microsoft 365 consent" />
      <RouteGate gate={['ProviderGrantsController_completeConsent_v1']}>
        <Callback body={body} />
      </RouteGate>
    </div>
  );
}
