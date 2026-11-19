'use client';

import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import { FormDialog, MutationError } from '@/features/domains/kit';
import {
  OUTBOUND_LABEL,
  errorHint,
  warningText,
  type ChangeSet,
  type MailFlowChange,
  type Preview,
} from './model';

/** Every query a gateway-side mail-flow change makes stale. */
export const CONNECTION_QUERIES = [
  'ProviderConnectionsController_get_v1',
  'ProviderConnectionsController_wizard_v1',
  'ProviderConnectionsController_list_v1',
  'ProviderDomainsController_list_v1',
  'ProviderMailFlowController_get_v1',
  'ProviderGuideController_get_v1',
  'ProviderHealthController_get_v1',
] as const;

type Disconnected = SuccessBody<'ProviderConnectionsController_disconnect_v1'>;

function Servers({ servers }: { servers: ChangeSet['domains'][number]['current']['servers'] }) {
  if (servers.length === 0) return <span className="text-muted-foreground">None</span>;
  return (
    <ul className="grid gap-0.5">
      {servers.map((s) => (
        <li key={`${s.host}:${s.port}:${s.priority}`} className="font-mono text-xs break-all">
          {s.host}:{s.port} <span className="text-muted-foreground">(priority {s.priority})</span>
        </li>
      ))}
    </ul>
  );
}

const FIELD_LABEL: Record<string, string> = {
  status: 'Connection status',
  outboundMode: 'Outbound mode',
  internalRouting: 'Internal routing',
  relayProof: 'Tenant proof policy',
};

function fieldValue(field: string, value: unknown): string {
  if (field === 'outboundMode' && typeof value === 'string' && value in OUTBOUND_LABEL) {
    return OUTBOUND_LABEL[value as keyof typeof OUTBOUND_LABEL];
  }
  if (typeof value === 'boolean') return value ? 'On' : 'Off';
  if (value === null || value === undefined) return 'Default';
  if (typeof value === 'string') return humanize(value);
  return JSON.stringify(value);
}

/** The server-computed change set of a preview (D13): rendered, never recomputed here. */
export function ChangeSetView({ changeSet }: { changeSet: ChangeSet }) {
  const changedDomains = changeSet.domains.filter((d) => d.changed);
  const unchanged = changeSet.domains.length - changedDomains.length;
  const nothing =
    changedDomains.length === 0 &&
    (changeSet.connector?.action ?? 'none') === 'none' &&
    changeSet.connection.length === 0 &&
    changeSet.grantsRevoked === 0;
  return (
    <div className="grid gap-3 text-sm" data-testid="change-set">
      {nothing ? <p>The gateway configuration already matches; nothing changes.</p> : null}
      {changedDomains.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[28rem] text-left text-sm">
            <caption className="sr-only">Destination changes per domain</caption>
            <thead>
              <tr className="border-b text-xs text-muted-foreground">
                <th scope="col" className="py-1 pr-3 font-medium">
                  Domain
                </th>
                <th scope="col" className="py-1 pr-3 font-medium">
                  Delivers to now
                </th>
                <th scope="col" className="py-1 font-medium">
                  Will deliver to
                </th>
              </tr>
            </thead>
            <tbody>
              {changedDomains.map((d) => (
                <tr key={d.domainId} className="border-b align-top last:border-0">
                  <th scope="row" className="py-2 pr-3 font-medium">
                    {d.name}
                  </th>
                  <td className="py-2 pr-3">
                    <Servers servers={d.current.servers} />
                  </td>
                  <td className="py-2">
                    <Servers servers={d.proposed.servers} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {unchanged > 0 ? (
        <p className="text-xs text-muted-foreground">
          {unchanged} domain{unchanged === 1 ? '' : 's'} already deliver
          {unchanged === 1 ? 's' : ''} to the provider and stay unchanged.
        </p>
      ) : null}
      {changeSet.connector && changeSet.connector.action !== 'none' ? (
        <p>
          Provider relay connector: <strong>{humanize(changeSet.connector.action)}</strong>
        </p>
      ) : null}
      {changeSet.connection.length > 0 ? (
        <ul className="grid gap-1">
          {changeSet.connection.map((c) => (
            <li key={c.field}>
              {FIELD_LABEL[c.field] ?? humanize(c.field)}: {fieldValue(c.field, c.from)} →{' '}
              <strong>{fieldValue(c.field, c.to)}</strong>
            </li>
          ))}
        </ul>
      ) : null}
      {changeSet.grantsRevoked > 0 ? (
        <p>
          Access grants revoked and credentials wiped: <strong>{changeSet.grantsRevoked}</strong>
        </p>
      ) : null}
    </div>
  );
}

/**
 * Preview → impact token → apply for one gateway-side mail-flow change (D13, ADR-0080): the
 * dialog previews on open, shows the server's change set and warnings, and applies only after the
 * administrator types the connection name (and ticks the stated effect). A `409 impact_changed`
 * previews again and asks for a new confirmation. `kind: 'disable'` disconnects the connection.
 */
export function MailFlowDialog({
  open,
  onOpenChange,
  connectionId,
  connectionName,
  change,
  title,
  effect,
  confirmLabel,
  destructive = false,
  onApplied,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  connectionId: string;
  connectionName: string;
  change: MailFlowChange;
  title: string;
  /** The statement the administrator ticks, naming the effect. */
  effect: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  onApplied?: (result: { disconnected?: Disconnected }) => void;
}) {
  const typedId = useId();
  const effectId = useId();
  const [preview, setPreview] = useState<Preview | null>(null);
  const [changed, setChanged] = useState(false);
  const [typed, setTyped] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const previewing = useApiMutation('ProviderMailFlowController_preview_v1', {
    successMessage: null,
  });
  const apply = useApiMutation('ProviderMailFlowController_apply_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Change applied.',
  });
  const disconnect = useApiMutation('ProviderConnectionsController_disconnect_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Connection disconnected.',
  });
  const changeKey = JSON.stringify(change);
  const started = useRef<string | null>(null);

  const runPreview = async () => {
    const outcome = await previewing.submit({ path: { id: connectionId }, body: { change } });
    if (outcome.ok) setPreview(outcome.data);
  };

  useEffect(() => {
    if (!open) {
      started.current = null;
      setPreview(null);
      setChanged(false);
      setTyped('');
      setAcknowledged(false);
      return;
    }
    if (started.current === changeKey) return;
    started.current = changeKey;
    void runPreview();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one preview per opened change
  }, [open, changeKey]);

  const applyError: ApiError | null = change.kind === 'disable' ? disconnect.error : apply.error;
  const busy = previewing.isPending || apply.isPending || disconnect.isPending;
  const ready = preview !== null && typed === connectionName && acknowledged && !busy;

  type Outcome = { ok: true; data: unknown } | { ok: false; error: ApiError };

  const settle = async (outcome: Outcome) => {
    if (outcome.ok) {
      onApplied?.(change.kind === 'disable' ? { disconnected: outcome.data as Disconnected } : {});
      onOpenChange(false);
      return;
    }
    if (outcome.error.code === 'impact_changed') {
      // The change set moved under us: show the new one and ask again (never apply blindly).
      setChanged(true);
      setTyped('');
      setAcknowledged(false);
      setPreview(null);
      await runPreview();
    }
  };

  const confirm = async () => {
    if (!preview || !ready) return;
    await settle(
      change.kind === 'disable'
        ? await disconnect.submit({
            path: { id: connectionId },
            body: { impactToken: preview.impactToken, confirm: true },
          })
        : await apply.submit({
            path: { id: connectionId },
            body: { change, impactToken: preview.impactToken, confirm: true },
          }),
    );
  };

  /** Retries the same intent with the same Idempotency-Key (P8). */
  const retry = async () => {
    await settle(change.kind === 'disable' ? await disconnect.retry() : await apply.retry());
  };

  return (
    <FormDialog
      open={open}
      onOpenChange={(next) => {
        if (!busy) onOpenChange(next);
      }}
      title={title}
      wide
      description="Review exactly what the gateway will change. Nothing changes in your Microsoft 365 or Google Workspace tenant."
    >
      <div className="grid min-w-0 gap-4">
        {changed ? (
          <p
            role="alert"
            className="rounded-md bg-tone-warning px-3 py-2 text-sm text-tone-warning-foreground"
          >
            The configuration changed since your preview. Review the updated changes below and
            confirm again.
          </p>
        ) : null}
        {previewing.isPending ? <LoadingState label="Computing the changes" rows={3} /> : null}
        {previewing.error ? (
          <div className="grid gap-2">
            <MutationError error={previewing.error} />
            {errorHint(previewing.error.code) ? (
              <p className="text-xs text-muted-foreground">{errorHint(previewing.error.code)}</p>
            ) : null}
            <Button
              variant="outline"
              className="justify-self-start"
              onClick={() => void runPreview()}
            >
              Preview again
            </Button>
          </div>
        ) : null}
        {preview ? (
          <>
            <ChangeSetView changeSet={preview.changeSet} />
            {preview.warnings.length > 0 ? (
              <ul
                className="grid gap-1 rounded-md border border-dashed p-3 text-sm"
                aria-label="Warnings"
              >
                {preview.warnings.map((w) => (
                  <li key={w}>{warningText(w)}</li>
                ))}
              </ul>
            ) : null}
            <p className="text-xs text-muted-foreground">
              This preview expires <DateTime value={preview.expiresAt} />.
            </p>
            <div className="flex items-start gap-2">
              <Checkbox
                id={effectId}
                checked={acknowledged}
                onCheckedChange={(v) => setAcknowledged(v === true)}
              />
              <Label htmlFor={effectId} className="leading-snug font-normal">
                {effect}
              </Label>
            </div>
            <div className="grid gap-2">
              <Label htmlFor={typedId}>
                Type <span className="font-mono">{connectionName}</span> to confirm
              </Label>
              <Input
                id={typedId}
                autoComplete="off"
                spellCheck={false}
                value={typed}
                onChange={(event) => setTyped(event.target.value)}
              />
            </div>
          </>
        ) : null}
        {applyError && applyError.code !== 'impact_changed' ? (
          <div className="grid gap-1">
            <MutationError error={applyError} />
            {errorHint(applyError.code) ? (
              <p className="text-xs text-muted-foreground">{errorHint(applyError.code)}</p>
            ) : null}
          </div>
        ) : null}
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {applyError && applyError.code !== 'impact_changed' && preview ? (
            <Button variant="outline" disabled={busy} onClick={() => void retry()}>
              Retry
            </Button>
          ) : null}
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={!ready}
            onClick={() => void confirm()}
          >
            {apply.isPending || disconnect.isPending ? 'Applying …' : confirmLabel}
          </Button>
        </div>
      </div>
    </FormDialog>
  );
}
