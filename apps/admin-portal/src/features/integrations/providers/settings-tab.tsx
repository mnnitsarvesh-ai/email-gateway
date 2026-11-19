'use client';

import Link from 'next/link';
import { useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { useApiMutation } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan, useHasPermission } from '@/lib/auth/me';
import { DetailList, MutationError, Section } from '@/features/domains/kit';
import { CONNECTION_QUERIES, MailFlowDialog } from './mail-flow-dialog';
import {
  AUTH_METHOD_INFO,
  GrantStatusBadge,
  errorHint,
  type Connection,
  type Grant,
  type MailFlowChange,
} from './model';

type Disconnected = SuccessBody<'ProviderConnectionsController_disconnect_v1'>;

export const renameSchema = z
  .object({
    displayName: z
      .string()
      .trim()
      .min(1, 'Enter a name')
      .max(128, 'At most 128 characters')
      .regex(/^[^\p{Cc}]+$/u, 'No control characters'),
  })
  .strict();

function RenameForm({ connection }: { connection: Connection }) {
  const [messages, setMessages] = useState<string[]>([]);
  const rename = useApiMutation('ProviderConnectionsController_update_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Connection renamed.',
  });
  const form = useZodForm(renameSchema, { defaultValues: { displayName: connection.displayName } });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await rename.submit({
      path: { id: connection.id },
      body: { displayName: values.displayName, rowVersion: connection.rowVersion },
    });
    if (!outcome.ok) setMessages(applyApiErrors(form, outcome.error));
  });
  return (
    <Form {...form}>
      <form
        className="grid max-w-md gap-3"
        noValidate
        aria-label="Rename connection"
        onSubmit={(event) => void submit(event)}
      >
        <FormErrorSummary messages={messages} requestId={rename.error?.requestId} />
        <FormField
          control={form.control}
          name="displayName"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Connection name</FormLabel>
              <FormControl>
                <Input autoComplete="off" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="justify-self-start" disabled={rename.isPending}>
          Save name
        </Button>
      </form>
    </Form>
  );
}

function Grants({ connection }: { connection: Connection }) {
  const [revoking, setRevoking] = useState<Grant | null>(null);
  const [removalSteps, setRemovalSteps] = useState<string[] | null>(null);
  const revoke = useApiMutation('ProviderGrantsController_revoke_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Access revoked at the gateway.',
  });
  const grants = connection.grants.filter((g) => g.status !== 'revoked');
  return (
    <div className="grid gap-3">
      {grants.length === 0 ? (
        <p className="text-sm text-muted-foreground">No access grant.</p>
      ) : (
        <ul className="grid gap-2">
          {grants.map((g) => (
            <li key={g.id} className="flex flex-wrap items-center gap-2 rounded-md border p-3">
              <code className="font-mono text-xs">{g.profile}</code>
              <span className="text-sm">{AUTH_METHOD_INFO[g.authMethod].title}</span>
              <GrantStatusBadge status={g.status} />
              {g.credentialFingerprint ? (
                <span className="text-xs text-muted-foreground">
                  credential {g.credentialFingerprint}
                </span>
              ) : null}
              <Can op="ProviderGrantsController_revoke_v1">
                <Button
                  size="sm"
                  variant="ghost"
                  className="ml-auto"
                  disabled={connection.status === 'disabled'}
                  onClick={() => setRevoking(g)}
                >
                  Revoke
                </Button>
              </Can>
            </li>
          ))}
        </ul>
      )}
      {removalSteps ? (
        <div className="grid gap-1 rounded-md border p-3 text-sm" role="status">
          <p className="font-medium">
            Finish the removal in your provider (the gateway cannot revoke consent there):
          </p>
          <ol className="list-decimal pl-5">
            {removalSteps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </div>
      ) : null}
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRevoking(null);
            revoke.reset();
          }
        }}
        title="Revoke the gateway’s access?"
        description="The grant is revoked and any stored credential is wiped at once. Health and validation stop working until access is granted again; mail flow is not changed. Refused while outbound routing is active."
        confirmLabel="Revoke access"
        destructive
        error={
          revoke.error ? (
            <div className="grid gap-1">
              <MutationError error={revoke.error} />
              {errorHint(revoke.error.code) ? (
                <p className="text-xs text-muted-foreground">{errorHint(revoke.error.code)}</p>
              ) : null}
            </div>
          ) : null
        }
        onConfirm={async () => {
          if (!revoking) return false;
          const outcome = await revoke.submit({
            path: { id: connection.id, profile: revoking.profile },
          });
          if (outcome.ok) setRemovalSteps(outcome.data.providerRemovalSteps);
          return outcome.ok;
        }}
      />
    </div>
  );
}

/** Tab "Settings": rename, outbound suspension, revoke grants, disconnect (D13). */
export function SettingsTab({ connection }: { connection: Connection }) {
  const canDisconnect = useCan('ProviderConnectionsController_disconnect_v1');
  const canConnector = useHasPermission('integration:manage', 'connector:manage');
  const [change, setChange] = useState<{
    change: MailFlowChange;
    title: string;
    effect: string;
    confirmLabel: string;
  } | null>(null);
  const [disconnected, setDisconnected] = useState<Disconnected | null>(null);
  const disabled = connection.status === 'disabled';
  const outboundOn =
    connection.outboundMode === 'active' || connection.outboundMode === 'probe_only';

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <Section title="General">
        <DetailList
          items={[
            {
              label: 'Connection ID',
              value: <code className="font-mono text-xs">{connection.id}</code>,
            },
            { label: 'Created', value: <DateTime value={connection.createdAt} mode="absolute" /> },
            ...(connection.disabledAt
              ? [{ label: 'Disconnected', value: <DateTime value={connection.disabledAt} /> }]
              : []),
          ]}
        />
        {disabled ? null : (
          <Can op="ProviderConnectionsController_update_v1">
            <RenameForm connection={connection} />
          </Can>
        )}
      </Section>
      <Section
        title="Access to your tenant"
        description="Revoking stops health checks and validation; the gateway never changes your tenant either way."
      >
        <Grants connection={connection} />
      </Section>
      {!disabled && canConnector && (outboundOn || connection.outboundMode === 'suspended') ? (
        <Section
          title="Outbound routing"
          description="Suspend answers your provider with a temporary failure (mail queues there and retries); turning outbound off removes the relay for this connection."
        >
          <div className="flex flex-wrap gap-2">
            {connection.outboundMode === 'active' ? (
              <Button
                variant="outline"
                onClick={() =>
                  setChange({
                    change: { kind: 'suspend' },
                    title: 'Suspend outbound routing',
                    effect:
                      'I understand that outbound and internal mail from this tenant is deferred by the gateway until I activate it again.',
                    confirmLabel: 'Suspend outbound',
                  })
                }
              >
                Suspend outbound
              </Button>
            ) : null}
            <Button
              variant="outline"
              onClick={() =>
                setChange({
                  change: { kind: 'disable_outbound' },
                  title: 'Turn outbound routing off',
                  effect:
                    'I understand that the gateway stops relaying mail for this tenant; I will remove the outbound connector or routing rule in my provider first.',
                  confirmLabel: 'Turn outbound off',
                })
              }
            >
              Turn outbound off
            </Button>
          </div>
        </Section>
      ) : null}
      {canDisconnect && !disabled ? (
        <Section
          title="Disconnect"
          description="Revokes access, wipes stored credentials, disables the provider relay and turns outbound off. Inbound destinations are kept so inbound mail keeps flowing; change them under Mail servers."
        >
          <Button
            variant="destructive"
            className="justify-self-start"
            onClick={() =>
              setChange({
                change: { kind: 'disable' },
                title: `Disconnect ${connection.displayName}`,
                effect:
                  'I understand that the gateway stops relaying this tenant’s outbound and internal mail and that I must remove the provider-side configuration.',
                confirmLabel: 'Disconnect',
              })
            }
          >
            Disconnect…
          </Button>
        </Section>
      ) : null}
      {disconnected ? (
        <Section title="Finish in your provider">
          <ol className="grid list-decimal gap-1 pl-5 text-sm">
            {disconnected.providerCleanupSteps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
          <p className="text-sm">
            Inbound destinations were kept.{' '}
            <Link href="/mail-servers?tab=destinations" className="underline">
              Review destination servers
            </Link>
            .
          </p>
        </Section>
      ) : null}
      {change ? (
        <MailFlowDialog
          open
          onOpenChange={(open) => !open && setChange(null)}
          connectionId={connection.id}
          connectionName={connection.displayName}
          change={change.change}
          title={change.title}
          effect={change.effect}
          confirmLabel={change.confirmLabel}
          destructive
          onApplied={(result) => {
            if (result.disconnected) setDisconnected(result.disconnected);
          }}
        />
      ) : null}
    </div>
  );
}
