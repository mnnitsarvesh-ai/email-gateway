'use client';

import { KeyRoundIcon } from 'lucide-react';
import { useId, useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useApiMutation } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';
import { LabelledSelect, MutationError } from './kit';
import type { DomainDetail } from './model';

type DkimKey = DomainDetail['dkimKeys'][number];
type Rotation = SuccessBody<'DomainDnsController_rotate_v1'>;

const KEY_TONE: Record<DkimKey['status'], Tone> = {
  pending: 'warning',
  active: 'success',
  rotating: 'info',
  retired: 'neutral',
  revoked: 'neutral',
};

const ALGORITHMS = [
  { value: 'rsa_2048', label: 'RSA 2048 (default, signs outbound mail)' },
  { value: 'ed25519', label: 'Ed25519' },
] as const;

/** DKIM keys of a domain and the rotation (`POST /domains/{id}/dkim/rotate`, `domain:dkim_rotate`). */
export function DkimPanel({ domain }: { domain: DomainDetail }) {
  const [open, setOpen] = useState(false);
  const [algorithm, setAlgorithm] = useState<'rsa_2048' | 'ed25519'>('rsa_2048');
  const [result, setResult] = useState<Rotation | null>(null);
  const selectId = useId();
  const rotate = useApiMutation('DomainDnsController_rotate_v1', {
    successMessage: 'DKIM rotation started. Publish the new record.',
    invalidates: [
      'DomainsController_get_v1',
      'DomainDnsController_dnsRecords_v1',
      'DomainDnsController_status_v1',
    ],
  });

  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      {domain.dkimKeys.length === 0 ? (
        <EmptyState icon={KeyRoundIcon} title="No DKIM keys" />
      ) : (
        <ul className="grid gap-2" aria-label="DKIM keys">
          {domain.dkimKeys.map((key) => (
            <li
              key={key.selector}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-sm"
            >
              <span className="grid gap-0.5">
                <code className="font-mono text-xs break-all">{key.host}</code>
                <span className="text-xs text-muted-foreground">
                  {humanize(key.algorithm)} · created <DateTime value={key.createdAt} />
                  {key.retireAfter ? (
                    <>
                      {' '}
                      · retires <DateTime value={key.retireAfter} />
                    </>
                  ) : null}
                </span>
              </span>
              <ToneBadge tone={KEY_TONE[key.status] ?? 'neutral'}>{humanize(key.status)}</ToneBadge>
            </li>
          ))}
        </ul>
      )}
      {result ? (
        <div className="grid gap-2 rounded-md border border-dashed p-3 text-sm" role="status">
          <p className="font-medium">
            Publish this TXT record now. The new key becomes active once the check finds it; the
            previous key keeps signing for {result.overlapDays} days.
          </p>
          <span className="flex min-w-0 items-center gap-1">
            <code className="font-mono text-xs break-all">{result.dnsRecord.host}</code>
            <CopyButton value={result.dnsRecord.host} label="Copy new DKIM host" />
          </span>
          <span className="flex min-w-0 items-start gap-1">
            <code className="rounded-sm bg-muted px-1.5 py-1 font-mono text-xs break-all">
              {result.dnsRecord.value}
            </code>
            <CopyButton value={result.dnsRecord.value} label="Copy new DKIM value" />
          </span>
          <Button
            variant="ghost"
            size="sm"
            className="justify-self-start"
            onClick={() => setResult(null)}
          >
            Dismiss
          </Button>
        </div>
      ) : null}
      <Can op="DomainDnsController_rotate_v1">
        <Button variant="outline" className="justify-self-start" onClick={() => setOpen(true)}>
          Rotate DKIM key
        </Button>
      </Can>
      <ConfirmDialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) rotate.reset();
        }}
        title="Rotate the DKIM key?"
        confirmLabel="Rotate key"
        description={
          <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
            <p>
              A new key is created whose TXT record you must publish at your DNS provider. Until the
              record is published and found, outbound mail keeps being signed with the current key.
              Do not remove the old record before the overlap ends.
            </p>
            <LabelledSelect
              id={selectId}
              label="Algorithm"
              value={algorithm}
              onChange={(value) => setAlgorithm(value as 'rsa_2048' | 'ed25519')}
              options={ALGORITHMS}
            />
          </div>
        }
        error={<MutationError error={rotate.error} />}
        onConfirm={async () => {
          const outcome = await rotate.submit({
            path: { id: domain.id },
            body: { algorithm },
          });
          if (outcome.ok) setResult(outcome.data);
          return outcome.ok;
        }}
      />
    </div>
  );
}
