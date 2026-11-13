'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useId, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { type ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan, useMe } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { DetailList, FormDialog, QueryView, Section, isUuid } from '@/features/domains/kit';
import { NO_ESCALATION_HINT, ROLE_KEY, UserStatusBadge } from './model';
import { RolePicker } from './role-picker';

type UserDetail = SuccessBody<'UsersController_get_v1'>;

/** PATCH /users/{id}: `{ displayName?, email? }`; only changed fields are sent. */
export const profileSchema = z
  .object({
    displayName: z.string().trim().min(1, 'Enter a name').max(255),
    email: z.string().trim().email('Enter an email address').max(320),
  })
  .strict();

export function profileBody(
  user: Pick<UserDetail, 'displayName' | 'email'>,
  values: z.output<typeof profileSchema>,
): RequestBody<'UsersController_update_v1'> {
  return {
    ...(values.displayName !== user.displayName ? { displayName: values.displayName } : {}),
    ...(values.email.toLowerCase() !== user.email.toLowerCase() ? { email: values.email } : {}),
  };
}

/** PUT /users/{id}/roles: `{ roleKeys[1..20] }`. */
export const rolesSchema = z
  .object({
    roleKeys: z.array(z.string().regex(ROLE_KEY)).min(1, 'Keep at least one role').max(20),
  })
  .strict();

/** PATCH /users/{id}/status: `{ status: active | disabled, reason? (1–512) }`. */
export const userStatusSchema = z
  .object({ status: z.enum(['active', 'disabled']), reason: z.string().trim().max(512) })
  .strict();

export function userStatusBody(
  values: z.output<typeof userStatusSchema>,
): RequestBody<'UsersController_changeStatus_v1'> {
  return values.reason
    ? { status: values.status, reason: values.reason }
    : { status: values.status };
}

function escalationAware(error: ApiError | null) {
  if (!error) return null;
  return (
    <div className="grid gap-2">
      <ErrorState error={error} compact />
      {error.status === 403 && error.code !== 'mfa_required' ? (
        <p className="text-xs text-muted-foreground">{NO_ESCALATION_HINT}</p>
      ) : null}
      {error.code === 'mfa_required' ? (
        <p className="text-xs text-muted-foreground">
          This action needs an MFA session: sign out and sign in again with your authenticator.
        </p>
      ) : null}
    </div>
  );
}

function ProfileForm({ user, onDone }: { user: UserDetail; onDone: () => void }) {
  const [messages, setMessages] = useState<string[]>([]);
  const update = useApiMutation('UsersController_update_v1', {
    invalidates: ['UsersController_get_v1', 'UsersController_list_v1'],
    successMessage: 'Profile saved.',
  });
  const form = useZodForm(profileSchema, {
    defaultValues: { displayName: user.displayName, email: user.email },
  });
  const submit = form.handleSubmit(async (values) => {
    const body = profileBody(user, values);
    if (Object.keys(body).length === 0) return onDone();
    setMessages([]);
    const outcome = await update.submit({ path: { id: user.id }, body });
    if (outcome.ok) return onDone();
    const lines = applyApiErrors(form, outcome.error);
    setMessages(outcome.error.status === 403 ? [...lines, NO_ESCALATION_HINT] : lines);
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Edit profile"
        onSubmit={(e) => void submit(e)}
      >
        <FormErrorSummary messages={messages} requestId={update.error?.requestId} />
        <FormField
          control={form.control}
          name="displayName"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Name (required)</FormLabel>
              <FormControl>
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email (required)</FormLabel>
              <FormControl>
                <Input type="email" {...field} />
              </FormControl>
              <FormDescription>
                Changing the email clears its verification and sends a new verification e-mail. Not
                possible under a platform override.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="justify-self-start" disabled={update.isPending}>
          {update.isPending ? 'Saving …' : 'Save profile'}
        </Button>
      </form>
    </Form>
  );
}

function RolesEditor({ user }: { user: UserDetail }) {
  const canEdit = useCan('UsersController_replaceRoles_v1');
  const current = user.roles.map((r) => r.key);
  const [value, setValue] = useState<string[]>(current);
  const [error, setError] = useState<string | undefined>();
  const save = useApiMutation('UsersController_replaceRoles_v1', {
    invalidates: ['UsersController_get_v1', 'UsersController_list_v1'],
    successMessage: 'Roles saved.',
  });
  const key = current.join(',');
  useEffect(() => setValue(key ? key.split(',') : []), [key]);
  const dirty = [...value].sort().join(',') !== [...current].sort().join(',');
  return (
    <Section
      title="Roles"
      description="Permissions come from roles; changes apply at the user's next request."
    >
      <ul className="flex flex-wrap gap-2" aria-label="Current roles">
        {user.roles.length === 0 ? (
          <li className="text-sm text-muted-foreground">No roles</li>
        ) : null}
        {user.roles.map((role) => (
          <li key={role.key}>
            <Badge variant="secondary">{role.name}</Badge>
          </li>
        ))}
      </ul>
      {canEdit ? (
        <form
          className="grid min-w-0 gap-3 [&>*]:min-w-0"
          aria-label="Change roles"
          onSubmit={(event) => {
            event.preventDefault();
            const parsed = rolesSchema.safeParse({ roleKeys: value });
            if (!parsed.success) return setError(parsed.error.issues[0]?.message);
            setError(undefined);
            void save.submit({ path: { id: user.id }, body: parsed.data });
          }}
        >
          <RolePicker legend="Assigned roles" value={value} onChange={setValue} error={error} />
          {escalationAware(save.error)}
          <Button type="submit" className="justify-self-start" disabled={!dirty || save.isPending}>
            {save.isPending ? 'Saving …' : 'Save roles'}
          </Button>
        </form>
      ) : null}
    </Section>
  );
}

function SessionsSection({ user }: { user: UserDetail }) {
  const sessions = useApiQuery('UsersController_listSessions_v1', { path: { id: user.id } });
  const [target, setTarget] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const revoke = useApiMutation('UsersController_revokeSession_v1', {
    invalidates: ['UsersController_listSessions_v1'],
    successMessage: 'Session signed out.',
  });
  const revokeAll = useApiMutation('UsersController_revokeAllSessions_v1', {
    invalidates: ['UsersController_listSessions_v1'],
    successMessage: 'Every session signed out.',
  });
  const rows = sessions.data?.data ?? [];
  return (
    <Section
      title="Sessions"
      description="Where the user is signed in."
      actions={
        rows.length > 0 ? (
          <Button variant="outline" size="sm" onClick={() => setAll(true)}>
            Sign out everywhere
          </Button>
        ) : null
      }
    >
      {sessions.isLoading ? (
        <LoadingState label="Loading sessions" rows={2} />
      ) : sessions.error ? (
        <ErrorState error={sessions.error} onRetry={() => void sessions.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState title="No active sessions" />
      ) : (
        <ul className="divide-y rounded-md border" aria-label="Sessions of the user">
          {rows.map((session) => (
            <li key={session.id} className="flex flex-wrap items-center gap-3 p-3 text-sm">
              <span className="grid min-w-0 flex-1 gap-0.5">
                <UntrustedText
                  value={session.userAgent}
                  emptyLabel="Unknown device"
                  maxLength={80}
                />
                <span className="text-xs text-muted-foreground">
                  {session.ipAddress ?? 'Unknown address'} · signed in{' '}
                  <DateTime value={session.authenticatedAt} /> · last used{' '}
                  <DateTime value={session.lastUsedAt} />
                  {session.mfaAuthenticated ? ' · MFA' : ''}
                </span>
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setTarget(session.id)}
                aria-label={`Sign out session from ${session.ipAddress ?? 'unknown address'}`}
              >
                Sign out
              </Button>
            </li>
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open) {
            setTarget(null);
            revoke.reset();
          }
        }}
        title="Sign out this session?"
        description="The device is signed out at its next request."
        confirmLabel="Sign out session"
        destructive
        error={escalationAware(revoke.error)}
        onConfirm={async () =>
          target ? (await revoke.submit({ path: { id: user.id, sessionId: target } })).ok : false
        }
      />
      <ConfirmDialog
        open={all}
        onOpenChange={(open) => {
          setAll(open);
          if (!open) revokeAll.reset();
        }}
        title={`Sign ${user.displayName} out everywhere?`}
        description="Every session of the user ends at its next request."
        confirmLabel="Sign out everywhere"
        destructive
        error={escalationAware(revokeAll.error)}
        onConfirm={async () => (await revokeAll.submit({ path: { id: user.id } })).ok}
      />
    </Section>
  );
}

function StatusAction({ user }: { user: UserDetail }) {
  const [target, setTarget] = useState<'active' | 'disabled' | null>(null);
  const [reason, setReason] = useState('');
  const reasonId = useId();
  const change = useApiMutation('UsersController_changeStatus_v1', {
    invalidates: [
      'UsersController_get_v1',
      'UsersController_list_v1',
      'UsersController_listSessions_v1',
    ],
    successMessage: 'Status changed.',
  });
  const label = (status: 'active' | 'disabled') =>
    status === 'disabled' ? 'Disable' : user.status === 'locked' ? 'Unlock' : 'Activate';
  return (
    <Can op="UsersController_changeStatus_v1">
      {user.status === 'disabled' || user.status === 'locked' ? (
        <Button variant="outline" onClick={() => setTarget('active')}>
          {label('active')}
        </Button>
      ) : null}
      {user.status !== 'disabled' ? (
        <Button variant="outline" onClick={() => setTarget('disabled')}>
          Disable
        </Button>
      ) : null}
      <ConfirmDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open) {
            setTarget(null);
            setReason('');
            change.reset();
          }
        }}
        title={target ? `${label(target)} ${user.displayName}?` : ''}
        destructive={target === 'disabled'}
        confirmLabel={target ? label(target) : 'Confirm'}
        description={
          <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
            <p>
              {target === 'disabled'
                ? 'The user cannot sign in and every session is signed out.'
                : 'The user can sign in again (a lockout is lifted).'}
            </p>
            <div className="grid gap-2">
              <Label htmlFor={reasonId}>Reason (optional)</Label>
              <Textarea
                id={reasonId}
                value={reason}
                maxLength={512}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
          </div>
        }
        error={escalationAware(change.error)}
        onConfirm={async () => {
          if (!target) return false;
          const parsed = userStatusSchema.parse({ status: target, reason });
          return (await change.submit({ path: { id: user.id }, body: userStatusBody(parsed) })).ok;
        }}
      />
    </Can>
  );
}

function UserDetailContent({ user }: { user: UserDetail }) {
  const router = useRouter();
  const me = useMe();
  const self = me.data?.user.id === user.id;
  const [editing, setEditing] = useState(false);
  const [resetMfa, setResetMfa] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const resend = useApiMutation('UsersController_resendInvitation_v1', { successMessage: null });
  const mfa = useApiMutation('UsersController_resetMfa_v1', {
    invalidates: ['UsersController_get_v1', 'UsersController_listSessions_v1'],
    successMessage: 'MFA reset. The user enrolls again at the next sign-in.',
  });
  const remove = useApiMutation('UsersController_remove_v1', {
    invalidates: ['UsersController_list_v1'],
    successMessage: `${user.displayName} deleted.`,
  });
  const canSessions = useCan('UsersController_listSessions_v1');

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title={user.displayName}
        breadcrumbs={[{ label: 'Users', href: '/users' }, { label: user.displayName }]}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            {user.email} <UserStatusBadge status={user.status} />
            {self ? <Badge variant="info">You</Badge> : null}
          </span>
        }
        actions={
          <>
            <Can op="UsersController_update_v1">
              <Button variant="outline" onClick={() => setEditing(true)}>
                Edit profile
              </Button>
            </Can>
            {user.status === 'invited' ? (
              <Can op="UsersController_resendInvitation_v1">
                <Button
                  variant="outline"
                  disabled={resend.isPending}
                  onClick={() => void resend.submit({ path: { id: user.id } })}
                >
                  Resend invitation
                </Button>
              </Can>
            ) : null}
            {!self ? <StatusAction user={user} /> : null}
          </>
        }
      />
      {resend.data ? (
        <p role="status" className="text-sm">
          Invitation sent again; it expires <DateTime value={resend.data.expiresAt} />.
        </p>
      ) : null}
      {escalationAware(resend.error)}
      <div className="grid min-w-0 gap-6 lg:grid-cols-2 [&>*]:min-w-0">
        <Section title="Profile">
          <DetailList
            items={[
              { label: 'User ID', value: <CopyableId value={user.id} label="user ID" /> },
              { label: 'Email verified', value: user.emailVerified ? 'Yes' : 'No' },
              { label: 'MFA', value: user.mfaEnabled ? 'Enabled' : 'Not enrolled' },
              { label: 'Status reason', value: user.statusReason ?? 'None' },
              {
                label: 'Locked until',
                value: (
                  <DateTime value={user.lockedUntil} mode="absolute" emptyLabel="Not locked" />
                ),
              },
              { label: 'Last sign-in', value: <DateTime value={user.lastLoginAt} /> },
              { label: 'Created', value: <DateTime value={user.createdAt} mode="absolute" /> },
            ]}
          />
          <div className="flex flex-wrap gap-2">
            {user.mfaEnabled ? (
              <Can op="UsersController_resetMfa_v1">
                <Button variant="outline" onClick={() => setResetMfa(true)}>
                  Reset MFA
                </Button>
              </Can>
            ) : null}
            {!self ? (
              <Can op="UsersController_remove_v1">
                <Button variant="ghost" onClick={() => setDeleting(true)}>
                  Delete user
                </Button>
              </Can>
            ) : null}
          </div>
        </Section>
        <RolesEditor user={user} />
      </div>
      {canSessions ? <SessionsSection user={user} /> : null}
      <FormDialog open={editing} onOpenChange={setEditing} title="Edit profile">
        <ProfileForm user={user} onDone={() => setEditing(false)} />
      </FormDialog>
      <ConfirmDialog
        open={resetMfa}
        onOpenChange={(open) => {
          setResetMfa(open);
          if (!open) mfa.reset();
        }}
        title={`Reset MFA of ${user.displayName}?`}
        description="The authenticator and recovery codes are removed and every session is signed out. Resetting needs your own MFA-authenticated session."
        confirmLabel="Reset MFA"
        destructive
        error={escalationAware(mfa.error)}
        onConfirm={async () => (await mfa.submit({ path: { id: user.id } })).ok}
      />
      <ConfirmDialog
        open={deleting}
        onOpenChange={(open) => {
          setDeleting(open);
          if (!open) remove.reset();
        }}
        title={`Delete ${user.displayName}?`}
        description="The user is removed from the organization and signed out everywhere."
        confirmLabel="Delete user"
        destructive
        typedConfirmation={user.email}
        error={escalationAware(remove.error)}
        onConfirm={async () => {
          const outcome = await remove.submit({ path: { id: user.id } });
          if (outcome.ok) router.push('/users');
          return outcome.ok;
        }}
      />
    </div>
  );
}

/** `/users/[userId]`: a foreign or unknown id is a 404. */
export function UserDetailPage({ userId }: { userId: string }) {
  return (
    <RouteGate gate={['UsersController_get_v1']}>
      <UserLoader userId={userId} />
    </RouteGate>
  );
}

function UserLoader({ userId }: { userId: string }) {
  const valid = isUuid(userId);
  const user = useApiQuery(
    'UsersController_get_v1',
    { path: { id: userId } },
    { enabled: valid, retry: false },
  );
  if (!valid) return <NotFoundView />;
  return (
    <QueryView query={user} label="user">
      {(data) => <UserDetailContent user={data} />}
    </QueryView>
  );
}
