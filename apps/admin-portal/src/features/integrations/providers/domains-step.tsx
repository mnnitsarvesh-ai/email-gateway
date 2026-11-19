'use client';

import Link from 'next/link';
import { useEffect, useId, useMemo, useState } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { MutationError } from '@/features/domains/kit';
import { CONNECTION_QUERIES } from './mail-flow-dialog';
import {
  PROVIDER_LABEL,
  ProviderVerificationBadge,
  errorHint,
  type Connection,
  type LinkedDomain,
} from './model';

/** Linked domains with the gateway and provider verification states (D4). */
export function LinkedDomainsTable({ domains }: { domains: readonly LinkedDomain[] }) {
  if (domains.length === 0) {
    return <p className="text-sm text-muted-foreground">No domain is linked yet.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[36rem] text-left text-sm">
        <caption className="sr-only">Linked domains</caption>
        <thead>
          <tr className="border-b text-xs text-muted-foreground">
            <th scope="col" className="py-1 pr-3 font-medium">
              Domain
            </th>
            <th scope="col" className="py-1 pr-3 font-medium">
              Gateway
            </th>
            <th scope="col" className="py-1 pr-3 font-medium">
              In the provider tenant
            </th>
            <th scope="col" className="py-1 pr-3 font-medium">
              Provider MX target
            </th>
            <th scope="col" className="py-1 font-medium">
              Inbound delivers to
            </th>
          </tr>
        </thead>
        <tbody>
          {domains.map((d) => (
            <tr key={d.id} className="border-b align-top last:border-0">
              <th scope="row" className="py-2 pr-3 font-medium">
                <Link href={`/domains/${d.id}`} className="underline-offset-4 hover:underline">
                  {d.name}
                </Link>
              </th>
              <td className="py-2 pr-3">{humanize(d.gatewayStatus)}</td>
              <td className="py-2 pr-3">
                <span className="grid gap-0.5">
                  <ProviderVerificationBadge value={d.providerVerification} />
                  {d.providerCheckedAt ? (
                    <span className="text-xs text-muted-foreground">
                      checked <DateTime value={d.providerCheckedAt} />
                    </span>
                  ) : null}
                </span>
              </td>
              <td className="py-2 pr-3 font-mono text-xs break-all">{d.providerMxHost ?? '—'}</td>
              <td className="py-2">
                {d.destinationProvider === null
                  ? 'No destination'
                  : d.destinationProvider === 'custom'
                    ? 'Custom servers'
                    : PROVIDER_LABEL[d.destinationProvider]}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Wizard step "Domains" (D4): choose which TXT-verified (gateway `active`) domains of the
 * organization this connection covers; the worker then checks each one in the provider tenant.
 */
export function DomainsStep({
  connection,
  linked,
}: {
  connection: Connection;
  linked: readonly LinkedDomain[];
}) {
  const searchId = useId();
  const canManage = useCan('ProviderDomainsController_replace_v1');
  const [q, setQ] = useState('');
  const query = q.trim().toLowerCase();
  const domains = useApiQuery('DomainsController_list_v1', {
    query: { status: 'active', limit: 100, ...(/^[a-z0-9.-]+$/.test(query) ? { q: query } : {}) },
  });
  const linkedIds = useMemo(
    () =>
      linked
        .map((d) => d.id)
        .sort()
        .join(','),
    [linked],
  );
  const [selected, setSelected] = useState<Set<string>>(() => new Set(linked.map((d) => d.id)));
  useEffect(() => {
    setSelected(new Set(linkedIds ? linkedIds.split(',') : []));
  }, [linkedIds]);
  const save = useApiMutation('ProviderDomainsController_replace_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Domains linked. The gateway checks them in the provider tenant now.',
  });
  const disabled = !canManage || connection.status === 'disabled';
  const options = [
    // Linked domains stay visible even when the search hides them.
    ...linked.map((d) => ({ id: d.id, name: d.name })),
    ...(domains.data?.data ?? [])
      .filter((d) => !linked.some((l) => l.id === d.id))
      .map((d) => ({ id: d.id, name: d.name })),
  ];
  const dirty = [...selected].sort().join(',') !== linkedIds;

  return (
    <div className="grid gap-4">
      <LinkedDomainsTable domains={linked} />
      {disabled ? null : (
        <fieldset className="grid gap-3 rounded-md border p-3">
          <legend className="px-1 text-sm font-medium">Domains covered by this connection</legend>
          <p className="text-xs text-muted-foreground">
            Only domains verified at the gateway (DNS TXT) can be linked; each domain belongs to at
            most one connection. Not listed? Add and verify it under{' '}
            <Link href="/domains" className="underline">
              Domains
            </Link>
            .
          </p>
          <div className="grid max-w-sm gap-1">
            <Label htmlFor={searchId}>Find a domain</Label>
            <Input
              id={searchId}
              value={q}
              autoComplete="off"
              onChange={(event) => setQ(event.target.value)}
            />
          </div>
          {domains.isLoading ? <LoadingState label="Loading domains" rows={3} /> : null}
          {domains.error ? (
            <ErrorState error={domains.error} onRetry={() => void domains.refetch()} compact />
          ) : null}
          <ul className="grid gap-2 sm:grid-cols-2">
            {options.map((d) => {
              const id = `link-${d.id}`;
              return (
                <li key={d.id} className="flex items-center gap-2">
                  <Checkbox
                    id={id}
                    checked={selected.has(d.id)}
                    onCheckedChange={(checked) =>
                      setSelected((prev) => {
                        const next = new Set(prev);
                        if (checked === true) next.add(d.id);
                        else next.delete(d.id);
                        return next;
                      })
                    }
                  />
                  <Label htmlFor={id} className="font-normal">
                    {d.name}
                  </Label>
                </li>
              );
            })}
          </ul>
          {domains.data?.nextCursor ? (
            <p className="text-xs text-muted-foreground">
              Showing the first 100 active domains; search to find others.
            </p>
          ) : null}
          {save.error ? (
            <div className="grid gap-1">
              <MutationError error={save.error} />
              {errorHint(save.error.code) ? (
                <p className="text-xs text-muted-foreground">{errorHint(save.error.code)}</p>
              ) : null}
            </div>
          ) : null}
          <Button
            className="justify-self-start"
            disabled={!dirty || save.isPending}
            onClick={() =>
              void save.submit({
                path: { id: connection.id },
                body: { domainIds: [...selected] },
              })
            }
          >
            {save.isPending ? 'Saving …' : 'Save linked domains'}
          </Button>
        </fieldset>
      )}
    </div>
  );
}
