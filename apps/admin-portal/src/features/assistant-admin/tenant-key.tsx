'use client';

import { useQueryClient } from '@tanstack/react-query';
import { KeyRoundIcon, ShieldCheckIcon, Trash2Icon } from 'lucide-react';
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { FormErrorSummary } from '@/components/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DetailList, LabelledSelect } from '@/features/domains/kit';
import { callOperation } from '@/lib/api/call';
import { ApiError } from '@/lib/api/errors';
import { emitSessionEvent } from '@/lib/session/events';
import type { Tone } from '@/lib/design/tokens';
import type { AssistantSettings, TenantKeyView } from '@/features/assistant/types';
import { adminErrorText, tenantKeyErrorText } from './model';

/**
 * The optional tenant-supplied provider key (design 34 D7, I27). The key is write-only: it lives
 * only in this form's state while the person types it, goes out once in the `PUT` body, and the
 * field is cleared after every submit (success or failure) and when the form unmounts. It is
 * never rendered back, stored in the query cache, logged or put in a URL: the calls go through
 * `callOperation` directly (no mutation cache, no retry that keeps the body), and the api answers
 * with the fingerprint and status only.
 */

const STATUS: Readonly<Record<TenantKeyView['status'], { label: string; tone: Tone }>> = {
  valid: { label: 'Valid', tone: 'success' },
  invalid: { label: 'Invalid', tone: 'danger' },
  unverified: { label: 'Not verified', tone: 'warning' },
};

const PROVIDER_LABEL: Readonly<Record<string, string>> = {
  anthropic: 'Anthropic',
  openai: 'OpenAI',
};

/** Printable ASCII, 20–512 characters (the api's `apiKey` rule; never echoed in messages). */
export const API_KEY_PATTERN = /^[\x21-\x7e]{20,512}$/;

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403 && error.code === 'mfa_required')
      emitSessionEvent({ type: 'mfa-required' });
    const coded = adminErrorText(error.code);
    if (coded) return coded;
    if (error.status === 400)
      return 'The provider or model is not offered, or the key is malformed.';
    return `${error.message} (${error.code})`;
  }
  return 'The request failed. Try again.';
}

/** The stored key: provider, model, fingerprint and status only (I27). */
export function TenantKeyDetails({ view }: { view: TenantKeyView }) {
  const status = STATUS[view.status];
  const lastError = tenantKeyErrorText(view.lastErrorCode);
  return (
    <DetailList
      items={[
        {
          label: 'Provider and model',
          value: `${PROVIDER_LABEL[view.provider] ?? view.provider} · ${view.model}`,
        },
        {
          label: 'Fingerprint',
          value: <code className="font-mono text-xs">{view.fingerprint}</code>,
        },
        { label: 'Status', value: <ToneBadge tone={status.tone}>{status.label}</ToneBadge> },
        {
          label: 'Stored',
          value: (
            <>
              <DateTime value={view.setAt} mode="absolute" />
              {view.setBy ? ` by ${view.setBy.displayName}` : ''}
            </>
          ),
        },
        {
          label: 'Last checked',
          value: <DateTime value={view.lastValidatedAt} mode="absolute" emptyLabel="Never" />,
        },
        ...(view.lastErrorCode
          ? [
              {
                label: 'Last error',
                value: (
                  <span>
                    {lastError} (<code className="font-mono text-xs">{view.lastErrorCode}</code>)
                  </span>
                ),
              },
            ]
          : []),
      ]}
    />
  );
}

export function TenantKeySection({ settings }: { settings: AssistantSettings }) {
  const queryClient = useQueryClient();
  const offered = settings.tenantKeysOffered;
  const stored = settings.tenantKey;
  const [provider, setProvider] = useState(stored?.provider ?? offered.providers[0] ?? '');
  const [model, setModel] = useState(stored?.model ?? offered.models[0] ?? '');
  const [apiKey, setApiKey] = useState('');
  const [pending, setPending] = useState<'set' | 'validate' | 'remove' | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const keyRef = useRef<HTMLInputElement>(null);
  const keyId = useId();
  const keyHelpId = useId();

  // Unmount: drop whatever was typed (also from the DOM node, e.g. for the bfcache).
  useEffect(() => {
    const input = keyRef.current;
    return () => {
      if (input) input.value = '';
    };
  }, []);

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['AssistantSettingsController_get_v1'] });

  if (!offered.enabled) {
    return (
      <div className="grid gap-2 text-sm">
        <p className="rounded-md border border-dashed px-3 py-2 text-muted-foreground">
          Using your organization&apos;s own AI provider key is not offered by the platform. The
          assistant uses the platform&apos;s provider account; your daily budgets apply either way.
        </p>
        {stored ? <TenantKeyDetails view={stored} /> : null}
      </div>
    );
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const value = apiKey;
    // Cleared before the request leaves: the field never shows the key again.
    setApiKey('');
    setErrors([]);
    setNotice(null);
    if (!API_KEY_PATTERN.test(value)) {
      setErrors(['Enter the key as the provider shows it: 20 to 512 characters, no spaces.']);
      return;
    }
    setPending('set');
    try {
      await callOperation('AssistantProviderKeyController_set_v1', {
        body: {
          expectedRowVersion: settings.rowVersion,
          provider: provider as 'anthropic' | 'openai',
          model,
          apiKey: value,
        },
      });
      setNotice('The key was checked with the provider and stored.');
      await refresh();
    } catch (error) {
      setErrors([errorMessage(error)]);
    } finally {
      setPending(null);
    }
  };

  const validate = async () => {
    setErrors([]);
    setNotice(null);
    setPending('validate');
    try {
      const view = await callOperation('AssistantProviderKeyController_validate_v1');
      setNotice(
        view.status === 'valid'
          ? 'The provider accepted the key.'
          : `The key is ${STATUS[view.status].label.toLowerCase()}.`,
      );
      await refresh();
    } catch (error) {
      setErrors([errorMessage(error)]);
    } finally {
      setPending(null);
    }
  };

  const remove = async () => {
    setErrors([]);
    setNotice(null);
    setPending('remove');
    try {
      // The CAS travels as the `expectedRowVersion` query parameter (WP3 item 6).
      await callOperation('AssistantProviderKeyController_remove_v1', {
        query: { expectedRowVersion: settings.rowVersion },
      });
      setNotice('The key was removed. Questions use the platform’s provider again.');
      await refresh();
      return true;
    } catch (error) {
      setErrors([errorMessage(error)]);
      return false;
    } finally {
      setPending(null);
    }
  };

  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">
        Store an API key of your organization&apos;s own{' '}
        {offered.providers.map((p) => PROVIDER_LABEL[p] ?? p).join(' or ')} account. It is checked
        with the provider before it is stored, encrypted, and never shown again: only its
        fingerprint and status are. Changing it needs a session signed in with multi-factor
        authentication.
      </p>
      <FormErrorSummary messages={errors} />
      {notice ? (
        <p role="status" className="text-sm">
          {notice}
        </p>
      ) : null}
      {stored ? (
        <div className="grid gap-3">
          <TenantKeyDetails view={stored} />
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void validate()}
              disabled={pending !== null}
            >
              <ShieldCheckIcon aria-hidden />
              {pending === 'validate' ? 'Checking …' : 'Check the key again'}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setRemoving(true)}
              disabled={pending !== null}
            >
              <Trash2Icon aria-hidden />
              Remove the key
            </Button>
          </div>
        </div>
      ) : (
        <p className="text-sm">No key is stored.</p>
      )}
      <form
        onSubmit={(event) => void submit(event)}
        className="grid max-w-xl gap-4 rounded-md border p-4"
        aria-label={stored ? 'Replace the provider key' : 'Store a provider key'}
        noValidate
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <LabelledSelect
            id={`${keyId}-provider`}
            label="Provider"
            value={provider}
            onChange={setProvider}
            options={offered.providers.map((value) => ({
              value,
              label: PROVIDER_LABEL[value] ?? value,
            }))}
          />
          <LabelledSelect
            id={`${keyId}-model`}
            label="Model"
            value={model}
            onChange={setModel}
            options={offered.models.map((value) => ({ value, label: value }))}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={keyId}>API key</Label>
          <Input
            id={keyId}
            ref={keyRef}
            type="password"
            name="assistant-provider-key"
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            data-1p-ignore
            data-lpignore="true"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            aria-describedby={keyHelpId}
            className="font-mono"
          />
          <p id={keyHelpId} className="text-xs text-muted-foreground">
            Write-only. The field is emptied when you submit.
          </p>
        </div>
        <Button
          type="submit"
          className="justify-self-start"
          disabled={pending !== null || !provider || !model}
        >
          <KeyRoundIcon aria-hidden />
          {pending === 'set'
            ? 'Checking and storing …'
            : stored
              ? 'Replace the key'
              : 'Store the key'}
        </Button>
      </form>
      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title="Remove the provider key"
        description={
          <p>
            The stored key is deleted and questions use the platform&apos;s provider again. Store a
            key again to use your own account.
          </p>
        }
        confirmLabel="Remove the key"
        destructive
        onConfirm={remove}
      />
    </div>
  );
}
