'use client';

import { useId, useState } from 'react';
import { z } from 'zod';
import { CopyButton } from '@/components/copy-button';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary, PasswordInput, applyApiErrors, useZodForm } from '@/components/form';
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
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { DetailList, MutationError } from '@/features/domains/kit';
import { CONNECTION_QUERIES } from './mail-flow-dialog';
import {
  AUTH_METHOD_INFO,
  GrantStatusBadge,
  MAIL_FLOW_PROFILE,
  errorHint,
  type AuthMethod,
  type CatalogProfile,
  type Connection,
  type Grant,
} from './model';
import { openConsentUrl } from './navigate';

type Delegation = NonNullable<SuccessBody<'ProviderGrantsController_create_v1'>['delegation']>;

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** PUT …/credentials for `customer_app_secret` (D2): tenant id, client id, secret, expiry. */
export const m365CredentialsSchema = z
  .object({
    tenantId: z.string().trim().regex(GUID, 'Enter the directory (tenant) ID, a GUID'),
    clientId: z.string().trim().regex(GUID, 'Enter the application (client) ID, a GUID'),
    clientSecret: z.string().min(1, 'Enter the client secret value').max(1024),
    expiresAt: z.string().regex(/^(\d{4}-\d{2}-\d{2})?$/, 'Use the date picker'),
  })
  .strict();

export function m365CredentialsBody(values: z.output<typeof m365CredentialsSchema>) {
  return {
    tenantId: values.tenantId.toLowerCase(),
    clientId: values.clientId.toLowerCase(),
    clientSecret: values.clientSecret,
    ...(values.expiresAt ? { expiresAt: `${values.expiresAt}T00:00:00.000Z` } : {}),
  };
}

export const subjectEmailSchema = z
  .string()
  .trim()
  .min(3, 'Enter the delegated administrator’s address')
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Enter an e-mail address');

/**
 * Reads a service-account JSON key file in memory (never stored, never echoed): it must be a JSON
 * object of `type: service_account` with the fields the api requires; the api validates it again.
 */
export function parseServiceAccountKey(text: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('The file is not valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('The file is not a service account key.');
  }
  const key = parsed as Record<string, unknown>;
  if (key.type !== 'service_account') throw new Error('The file is not a service account key.');
  for (const field of ['client_email', 'private_key', 'private_key_id', 'token_uri']) {
    if (typeof key[field] !== 'string' || !key[field]) {
      throw new Error(`The key file has no ${field}.`);
    }
  }
  return key;
}

function ErrorHint({ error }: { error: ApiError | null }) {
  if (!error) return null;
  const hint = errorHint(error.code);
  return (
    <div className="grid gap-1">
      <MutationError error={error} />
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function PermissionList({ title, items }: { title: string; items: readonly string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="grid gap-1">
      <p className="text-xs font-medium text-muted-foreground">{title}</p>
      <ul className="list-disc pl-5 font-mono text-xs break-all">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

/** Customer app registration secret (Microsoft 365, `customer_app_secret`). */
function M365CredentialsForm({ connectionId, profile }: { connectionId: string; profile: string }) {
  const [messages, setMessages] = useState<string[]>([]);
  const upload = useApiMutation('ProviderGrantsController_setCredentials_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Credentials stored encrypted. The gateway is verifying them.',
  });
  const form = useZodForm(m365CredentialsSchema, {
    defaultValues: { tenantId: '', clientId: '', clientSecret: '', expiresAt: '' },
  });
  const submit = form.handleSubmit(async (values) => {
    setMessages([]);
    const outcome = await upload.submit({
      path: { id: connectionId, profile },
      body: m365CredentialsBody(values),
    });
    // The secret leaves the form state either way: it is never kept in the browser.
    form.setValue('clientSecret', '');
    if (!outcome.ok) return setMessages(applyApiErrors(form, outcome.error));
    form.reset();
  });
  return (
    <Form {...form}>
      <form
        className="grid max-w-xl gap-4"
        noValidate
        aria-label="App registration credentials"
        autoComplete="off"
        onSubmit={(event) => void submit(event)}
      >
        <FormErrorSummary messages={messages} requestId={upload.error?.requestId} />
        <FormField
          control={form.control}
          name="tenantId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Directory (tenant) ID</FormLabel>
              <FormControl>
                <Input autoComplete="off" spellCheck={false} className="font-mono" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="clientId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Application (client) ID</FormLabel>
              <FormControl>
                <Input autoComplete="off" spellCheck={false} className="font-mono" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="clientSecret"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Client secret value</FormLabel>
              <FormControl>
                <PasswordInput autoComplete="new-password" spellCheck={false} {...field} />
              </FormControl>
              <FormDescription>
                Stored encrypted; the gateway never shows it again (only a fingerprint).
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="expiresAt"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Secret expiry date (optional)</FormLabel>
              <FormControl>
                <Input type="date" {...field} />
              </FormControl>
              <FormDescription>Health warns 30 days and 7 days before it expires.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <Button type="submit" className="justify-self-start" disabled={upload.isPending}>
          {upload.isPending ? 'Uploading …' : 'Upload and verify'}
        </Button>
      </form>
    </Form>
  );
}

/** Customer service account key (Google Workspace, `customer_service_account`). */
function GoogleKeyForm({ connectionId, profile }: { connectionId: string; profile: string }) {
  const fileId = useId();
  const subjectId = useId();
  const [key, setKey] = useState<Record<string, unknown> | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [subject, setSubject] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const upload = useApiMutation('ProviderGrantsController_setCredentials_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Key stored encrypted. The gateway is verifying it.',
  });
  const readFile = async (file: File | undefined) => {
    setProblem(null);
    setKey(null);
    setFileName(null);
    if (!file) return;
    if (file.size > 16_384) return setProblem('The file is too large for a service account key.');
    try {
      setKey(parseServiceAccountKey(await file.text()));
      setFileName(file.name);
    } catch (error) {
      setProblem(error instanceof Error ? error.message : 'The file could not be read.');
    }
  };
  const submit = async () => {
    const email = subjectEmailSchema.safeParse(subject);
    if (!email.success) return setProblem(email.error.issues[0]?.message ?? 'Invalid address');
    if (!key) return setProblem('Choose the JSON key file.');
    const outcome = await upload.submit({
      path: { id: connectionId, profile },
      body: { serviceAccountKey: key, subjectEmail: email.data },
    });
    // The key leaves memory either way.
    setKey(null);
    setFileName(null);
    if (outcome.ok) setSubject('');
  };
  return (
    <form
      className="grid max-w-xl gap-4"
      noValidate
      aria-label="Service account key"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <div className="grid gap-2">
        <Label htmlFor={fileId}>Service account JSON key</Label>
        <Input
          id={fileId}
          type="file"
          accept="application/json,.json"
          onChange={(event) => void readFile(event.target.files?.[0])}
        />
        <p className="text-xs text-muted-foreground">
          {fileName
            ? `Selected: ${fileName}. The key is read in this tab only and sent once.`
            : 'Read in this tab only, sent once, stored encrypted; never shown again.'}
        </p>
      </div>
      <div className="grid gap-2">
        <Label htmlFor={subjectId}>Delegated administrator</Label>
        <Input
          id={subjectId}
          type="email"
          autoComplete="off"
          value={subject}
          onChange={(event) => setSubject(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          Ideally a dedicated administrator with a custom read-only role.
        </p>
      </div>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {problem}
        </p>
      ) : null}
      <ErrorHint error={upload.error} />
      <Button type="submit" className="justify-self-start" disabled={upload.isPending}>
        {upload.isPending ? 'Uploading …' : 'Upload and verify'}
      </Button>
    </form>
  );
}

/** Google domain-wide delegation to the platform service account (D3.5). */
function DelegationSteps({
  connectionId,
  profile,
  delegation,
}: {
  connectionId: string;
  profile: string;
  delegation: Pick<Delegation, 'clientId' | 'scopes'> & { adminConsoleSteps?: string[] };
}) {
  const subjectId = useId();
  const [subject, setSubject] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const verify = useApiMutation('ProviderGrantsController_verify_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Delegation recorded. The gateway is verifying it.',
  });
  const scopes = delegation.scopes.join(',');
  return (
    <div className="grid gap-4">
      <ol className="grid list-decimal gap-2 pl-5 text-sm">
        {(delegation.adminConsoleSteps?.length
          ? delegation.adminConsoleSteps
          : [
              'In the Google Admin console open Security → Access and data control → API controls → Manage domain-wide delegation.',
              'Add a new API client with the client ID and the OAuth scopes below (exactly these, comma-separated).',
              'Name a delegated administrator below and confirm.',
            ]
        ).map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      <DetailList
        items={[
          {
            label: 'Client ID',
            value: (
              <span className="inline-flex items-center gap-1 font-mono text-xs">
                {delegation.clientId}
                <CopyButton value={delegation.clientId} label="Copy client ID" />
              </span>
            ),
          },
          {
            label: 'OAuth scopes',
            value: (
              <span className="inline-flex items-start gap-1 font-mono text-xs break-all">
                {scopes}
                <CopyButton value={scopes} label="Copy OAuth scopes" />
              </span>
            ),
          },
        ]}
      />
      <form
        className="grid max-w-xl gap-2"
        noValidate
        aria-label="Confirm delegation"
        onSubmit={(event) => {
          event.preventDefault();
          const email = subjectEmailSchema.safeParse(subject);
          if (!email.success) {
            setProblem(email.error.issues[0]?.message ?? 'Invalid address');
            return;
          }
          setProblem(null);
          void verify.submit({
            path: { id: connectionId, profile },
            body: { subjectEmail: email.data },
          });
        }}
      >
        <Label htmlFor={subjectId}>Delegated administrator</Label>
        <Input
          id={subjectId}
          type="email"
          autoComplete="off"
          value={subject}
          onChange={(event) => setSubject(event.target.value)}
        />
        {problem ? (
          <p role="alert" className="text-sm text-destructive">
            {problem}
          </p>
        ) : null}
        <ErrorHint error={verify.error} />
        <Button type="submit" className="justify-self-start" disabled={verify.isPending}>
          I have authorized the client, verify
        </Button>
      </form>
    </div>
  );
}

/** One auth method card (what is requested and why). */
function MethodCard({
  method,
  available,
  profile,
  onChoose,
  pending,
}: {
  method: AuthMethod;
  available: boolean;
  profile: CatalogProfile;
  onChoose: () => void;
  pending: boolean;
}) {
  const info = AUTH_METHOD_INFO[method];
  return (
    <li className="grid gap-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="font-medium">{info.title}</h4>
        {info.recommended ? <ToneBadge tone="success">Recommended</ToneBadge> : null}
        {info.secret ? <ToneBadge tone="neutral">Advanced</ToneBadge> : null}
      </div>
      <p className="text-sm text-muted-foreground">{info.summary}</p>
      <PermissionList
        title={`Read-only permissions requested (${profile.title})`}
        items={profile.permissions}
      />
      <Button
        variant={info.recommended ? 'default' : 'outline'}
        className="justify-self-start"
        disabled={!available || pending}
        onClick={onChoose}
      >
        {available ? `Use ${info.title.toLowerCase()}` : 'Not offered by this gateway'}
      </Button>
    </li>
  );
}

/** Status and details of the mail-flow grant (never a credential; fingerprint and dates only). */
function GrantDetails({ grant, connection }: { grant: Grant; connection: Connection }) {
  return (
    <DetailList
      items={[
        { label: 'Method', value: AUTH_METHOD_INFO[grant.authMethod].title },
        { label: 'Status', value: <GrantStatusBadge status={grant.status} /> },
        ...(grant.lastErrorCode
          ? [{ label: 'Last error', value: humanize(grant.lastErrorCode) }]
          : []),
        {
          label: 'Tenant',
          value: connection.tenantName
            ? `${connection.tenantName}${connection.tenantId ? ` (${connection.tenantId})` : ''}`
            : 'Not bound yet (bound when a linked domain is verified in the tenant)',
        },
        ...(grant.clientId ? [{ label: 'Client ID', value: grant.clientId }] : []),
        ...(grant.subjectEmail
          ? [{ label: 'Delegated administrator', value: grant.subjectEmail }]
          : []),
        ...(grant.credentialFingerprint
          ? [
              {
                label: 'Credential',
                value: (
                  <span>
                    Fingerprint <code className="font-mono">{grant.credentialFingerprint}</code>,
                    set <DateTime value={grant.credentialSetAt} />
                    {grant.credentialExpiresAt ? (
                      <>
                        , expires <DateTime value={grant.credentialExpiresAt} mode="absolute" />
                      </>
                    ) : null}
                  </span>
                ),
              },
            ]
          : []),
        { label: 'Verified', value: <DateTime value={grant.verifiedAt} /> },
        {
          label: 'Permissions',
          value: (
            <div className="grid gap-2">
              <PermissionList title="Granted" items={grant.observedPermissions ?? []} />
              <PermissionList title="Missing (grant them)" items={grant.missingPermissions ?? []} />
              <PermissionList
                title="Excess (over-privileged: remove them)"
                items={grant.excessPermissions ?? []}
              />
              {!grant.observedPermissions?.length && !grant.missingPermissions?.length ? (
                <span className="text-muted-foreground">Reported after verification</span>
              ) : null}
            </div>
          ),
        },
      ]}
    />
  );
}

/**
 * Wizard step "Connect" (D2, D3): auth method cards, the admin-consent button (same tab),
 * credential forms for customer-owned methods, Google delegation steps, grant status, re-verify
 * and start over.
 */
export function ConnectStep({
  connection,
  profile,
}: {
  connection: Connection;
  profile: CatalogProfile | undefined;
}) {
  const profileKey = MAIL_FLOW_PROFILE[connection.provider];
  const grant = connection.grants.find((g) => g.profile === profileKey && g.status !== 'revoked');
  const canManage = useCan('ProviderGrantsController_create_v1');
  const [delegation, setDelegation] = useState<Delegation | null>(null);
  const create = useApiMutation('ProviderGrantsController_create_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: null,
  });
  const verify = useApiMutation('ProviderGrantsController_verify_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Verification requested.',
  });
  const revoke = useApiMutation('ProviderGrantsController_revoke_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: null,
  });
  const disabled = connection.status === 'disabled';

  const choose = async (method: AuthMethod) => {
    const outcome = await create.submit({
      path: { id: connection.id },
      body: { profile: profileKey, authMethod: method },
    });
    if (!outcome.ok) return;
    const consentUrl = outcome.data.consent?.consentUrl;
    if (outcome.data.next === 'consent' && consentUrl) {
      // Same tab (§6): Microsoft redirects back to /integrations/providers/consent-callback.
      openConsentUrl(consentUrl);
      return;
    }
    if (outcome.data.next === 'delegation' && outcome.data.delegation) {
      setDelegation(outcome.data.delegation);
    }
    create.reset();
  };

  const startOver = async () => {
    if (!grant) return;
    const outcome = await revoke.submit({ path: { id: connection.id, profile: profileKey } });
    if (outcome.ok) setDelegation(null);
  };

  if (!profile) {
    return <p className="text-sm text-muted-foreground">The provider catalogue is unavailable.</p>;
  }

  if (!grant) {
    return (
      <div className="grid gap-3">
        <p className="text-sm">
          Choose how the gateway gets read-only access to your{' '}
          {connection.provider === 'microsoft_365' ? 'Microsoft 365 tenant' : 'Google Workspace'}.
          The gateway reads the tenant identity and domain verification only; it never reads mail or
          changes settings.
        </p>
        <ErrorHint error={create.error} />
        <ul className="grid gap-3 lg:grid-cols-2">
          {[...profile.authMethods]
            .sort(
              (a, b) =>
                Number(AUTH_METHOD_INFO[b].recommended) - Number(AUTH_METHOD_INFO[a].recommended),
            )
            .map((method) => (
              <MethodCard
                key={method}
                method={method}
                profile={profile}
                available={canManage && !disabled && profile.availableAuthMethods.includes(method)}
                pending={create.isPending}
                onChoose={() => void choose(method)}
              />
            ))}
        </ul>
      </div>
    );
  }

  const needsCredentials =
    (grant.authMethod === 'customer_app_secret' ||
      grant.authMethod === 'customer_service_account') &&
    (grant.credentialSetAt === null || grant.status === 'error');
  const delegationView =
    grant.authMethod === 'platform_service_account' && grant.status === 'pending_consent'
      ? (delegation ?? {
          clientId: grant.clientId ?? '',
          scopes: grant.requestedPermissions,
          adminConsoleSteps: [],
        })
      : null;

  return (
    <div className="grid gap-4">
      <GrantDetails grant={grant} connection={connection} />
      {grant.status === 'verifying' ? (
        <p role="status" className="text-sm text-muted-foreground">
          The gateway is verifying access in your tenant. This page updates by itself.
        </p>
      ) : null}
      {grant.authMethod === 'platform_app' && grant.status === 'pending_consent' ? (
        <p className="text-sm">
          The consent was not completed. Start over to open Microsoft’s consent page again (a new
          single-use link is created).
        </p>
      ) : null}
      {canManage && !disabled && delegationView ? (
        <DelegationSteps
          connectionId={connection.id}
          profile={profileKey}
          delegation={delegationView}
        />
      ) : null}
      {canManage && !disabled && needsCredentials ? (
        grant.authMethod === 'customer_app_secret' ? (
          <M365CredentialsForm connectionId={connection.id} profile={profileKey} />
        ) : (
          <GoogleKeyForm connectionId={connection.id} profile={profileKey} />
        )
      ) : null}
      <ErrorHint error={verify.error ?? revoke.error} />
      {canManage && !disabled ? (
        <div className="flex flex-wrap gap-2">
          {grant.status === 'error' || grant.status === 'active' ? (
            <Button
              variant="outline"
              disabled={verify.isPending}
              onClick={() =>
                void verify.submit({ path: { id: connection.id, profile: profileKey }, body: {} })
              }
            >
              Verify again
            </Button>
          ) : null}
          {grant.status !== 'active' ? (
            <Button variant="ghost" disabled={revoke.isPending} onClick={() => void startOver()}>
              Start over with another method
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
