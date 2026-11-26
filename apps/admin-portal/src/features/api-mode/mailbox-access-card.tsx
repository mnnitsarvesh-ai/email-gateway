'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Button } from '@/components/ui/button';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan, useHasPermission } from '@/lib/auth/me';
import { MutationError, Section } from '@/features/domains/kit';
import { ConnectStep } from '@/features/integrations/providers/connect-step';
import { CONNECTION_QUERIES } from '@/features/integrations/providers/mail-flow-dialog';
import type { CatalogProvider, Connection } from '@/features/integrations/providers/model';
import { MAILBOX_PROFILE, MAILBOX_PURPOSE } from './model';

export const MAILBOX_ACCESS_ANCHOR = 'mailbox-access';

const INTRO =
  'Choose how the gateway gets mailbox access for API mode. It reads new messages of the in-scope mailboxes for scanning (only when no journal copy was seen) and lists users to count mailboxes; from step API-2 it moves detected threats out of the mailbox.';

/** Permissions of the mailbox-access profiles (design D4), stated before any consent. */
const PERMISSION_TEXT: Record<Connection['provider'], string> = {
  microsoft_365:
    'Microsoft Graph application permissions Mail.ReadWrite (read new messages; move threats from step API-2) and User.Read.All (list mailboxes for coverage).',
  google_workspace:
    'Domain-wide delegation scopes gmail.modify (read new messages; move threats from step API-2) and admin.directory.user.readonly (list mailboxes for coverage).',
};

/**
 * "Mailbox access for API mode" on the connection page (step API-1 D4, D14): the 8.2 consent,
 * delegation and credential flows of the `*.mailbox_remediation` profile, and revoke. Separate
 * from the mail-flow and ATO grants (own app, own consent); granting and revoking also need
 * `remediation:write` (the api answers `403 remediation_permission_required` otherwise).
 */
export function MailboxAccessCard({
  connection,
  catalog,
}: {
  connection: Connection;
  catalog: CatalogProvider | undefined;
}) {
  const profileKey = MAILBOX_PROFILE[connection.provider];
  const profile = catalog?.profiles.find(
    (p) => p.key === profileKey || p.purpose === MAILBOX_PURPOSE,
  );
  const canWrite = useHasPermission('remediation:write');
  const canRevoke = useCan('ProviderGrantsController_revoke_v1') && canWrite;
  const grant = connection.grants.find((g) => g.profile === profileKey && g.status !== 'revoked');
  const [revoking, setRevoking] = useState(false);
  const [removalSteps, setRemovalSteps] = useState<string[] | null>(null);
  const revoke = useApiMutation('ProviderGrantsController_revoke_v1', {
    invalidates: [...CONNECTION_QUERIES, 'ApiModeController_listConnections_v1'],
    successMessage: 'Mailbox access revoked at the gateway.',
  });
  useEffect(() => {
    // The coverage page links here as `?tab=settings#mailbox-access`.
    if (window.location.hash.slice(1) === MAILBOX_ACCESS_ANCHOR) {
      document.getElementById(MAILBOX_ACCESS_ANCHOR)?.scrollIntoView?.({ block: 'start' });
    }
  }, []);
  return (
    <div id={MAILBOX_ACCESS_ANCHOR} className="scroll-mt-20">
      <Section
        title="Mailbox access for API mode"
        description={
          <span className="grid gap-1">
            <span>{PERMISSION_TEXT[connection.provider]}</span>
            <span>
              A separate grant with its own app: it does not change mail flow and is independent of
              the mail-flow access above and of account takeover response. Granting or revoking it
              needs the remediation write permission (Manage API-mode protection).
            </span>
          </span>
        }
      >
        {!canWrite ? (
          <p role="status" className="text-sm text-muted-foreground">
            You can see this grant; granting or revoking it needs the remediation write permission.
          </p>
        ) : null}
        {profile ? (
          <ConnectStep
            connection={connection}
            profile={profile}
            profileKey={profileKey}
            intro={INTRO}
            allowed={canWrite}
          />
        ) : (
          <p className="text-sm text-muted-foreground">
            The provider catalogue does not offer mailbox access on this gateway.
          </p>
        )}
        {grant && canRevoke && connection.status !== 'disabled' ? (
          <Button
            variant="outline"
            className="justify-self-start"
            onClick={() => setRevoking(true)}
          >
            Revoke mailbox access
          </Button>
        ) : null}
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
        <p className="text-sm">
          <Link href="/api-mode" className="text-primary underline underline-offset-2">
            Open mailbox protection
          </Link>{' '}
          for coverage, feeds and detections.
        </p>
      </Section>
      <ConfirmDialog
        open={revoking}
        onOpenChange={(open) => {
          if (!open) {
            setRevoking(false);
            revoke.reset();
          }
        }}
        title="Revoke mailbox access for API mode?"
        description="The grant is revoked and any stored credential is wiped at once. Mailbox feeds and the mailbox inventory stop; journal copies are still scanned. Mail flow is not changed."
        confirmLabel="Revoke mailbox access"
        destructive
        error={<MutationError error={revoke.error} />}
        onConfirm={async () => {
          const outcome = await revoke.submit({
            path: { id: connection.id, profile: profileKey },
          });
          if (outcome.ok) setRemovalSteps(outcome.data.providerRemovalSteps);
          return outcome.ok;
        }}
      />
    </div>
  );
}
