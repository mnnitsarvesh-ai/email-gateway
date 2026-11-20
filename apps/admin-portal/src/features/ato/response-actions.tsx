'use client';

import { useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { AtoReasonDialog, MfaRequiredNote, useMfaSession } from './components';
import {
  ACTION_LABELS,
  DURATION_OPTIONS,
  REQUESTABLE_ACTIONS,
  type AtoAccountKind,
  type AtoActionType,
  type AtoRequestBody,
  type AtoResponse,
} from './model';

/**
 * Response controls (§5.1 #16, #19–#22; ADR-0072): request, approve (MFA, not the requester),
 * reject, cancel and roll back (MFA). The api decides every rule (`canDecide`, `canRollback` are
 * its answer for the caller); the portal shows the MFA-required state instead of a dead button.
 */

const INVALIDATES = [
  'AtoResponsesController_list_v1',
  'AtoResponsesController_get_v1',
  'AtoRestrictionsController_list_v1',
  'AtoOverviewController_attention_v1',
  'AtoOverviewController_overview_v1',
  'AtoAccountsController_get_v1',
  'IncidentsController_get_v1',
  'IncidentsController_timeline_v1',
] as const;

type Dialog = 'approve' | 'reject' | 'cancel' | 'rollback' | null;

export function ResponseControls({ response }: { response: AtoResponse }) {
  const canRespond = useCan('AtoResponsesController_approve_v1');
  const mfa = useMfaSession();
  const [dialog, setDialog] = useState<Dialog>(null);
  const approve = useApiMutation('AtoResponsesController_approve_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Response approved',
  });
  const reject = useApiMutation('AtoResponsesController_reject_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Response rejected',
  });
  const cancel = useApiMutation('AtoResponsesController_cancel_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Response cancelled',
  });
  const rollback = useApiMutation('AtoResponsesController_rollback_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Response rolled back',
  });
  if (!canRespond) return null;
  const label = ACTION_LABELS[response.actionType];
  const pending = response.status === 'pending_approval';
  const path = { responseId: response.id };
  return (
    <div className="grid gap-1.5">
      <div className="flex flex-wrap gap-1.5">
        {pending && response.canDecide ? (
          <>
            <Button
              size="sm"
              disabled={!mfa}
              onClick={() => setDialog('approve')}
              aria-label={`Approve: ${label}`}
            >
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setDialog('reject')}
              aria-label={`Reject: ${label}`}
            >
              Reject
            </Button>
          </>
        ) : null}
        {pending ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setDialog('cancel')}
            aria-label={`Cancel: ${label}`}
          >
            Cancel request
          </Button>
        ) : null}
        {response.canRollback ? (
          <Button
            size="sm"
            variant="outline"
            disabled={!mfa}
            onClick={() => setDialog('rollback')}
            aria-label={`Roll back: ${label}`}
          >
            Roll back
          </Button>
        ) : null}
      </div>
      {pending && response.canDecide && !mfa ? <MfaRequiredNote action="Approving" /> : null}
      {response.canRollback && !mfa ? <MfaRequiredNote action="Rolling back" /> : null}
      {pending && !response.canDecide ? (
        <p className="text-xs text-muted-foreground">
          Waiting for another analyst: the requester cannot approve their own request.
        </p>
      ) : null}
      <AtoReasonDialog
        open={dialog === 'approve'}
        onOpenChange={(open) => setDialog(open ? 'approve' : null)}
        title={`Approve “${label}”?`}
        description={
          response.provider === 'gateway'
            ? 'Gateway responses take effect at once: restrictions are enforced by every SMTP adapter within seconds.'
            : 'The response is sent to the identity provider; it succeeds only when the provider confirms it.'
        }
        confirmLabel="Approve"
        required={false}
        minChars={1}
        pending={approve.isPending}
        onSubmit={(reason) => approve.submit({ path, body: reason ? { reason } : {} })}
        onRetry={approve.retry}
      />
      <AtoReasonDialog
        open={dialog === 'reject'}
        onOpenChange={(open) => setDialog(open ? 'reject' : null)}
        title={`Reject “${label}”?`}
        description="The request is closed without effect; the requester sees your reason."
        confirmLabel="Reject"
        destructive
        pending={reject.isPending}
        onSubmit={(reason) => reject.submit({ path, body: { reason: reason ?? '' } })}
        onRetry={reject.retry}
      />
      <AtoReasonDialog
        open={dialog === 'cancel'}
        onOpenChange={(open) => setDialog(open ? 'cancel' : null)}
        title={`Cancel “${label}”?`}
        description="The pending request is withdrawn without effect."
        confirmLabel="Cancel request"
        required={false}
        minChars={1}
        pending={cancel.isPending}
        onSubmit={(reason) => cancel.submit({ path, body: reason ? { reason } : {} })}
        onRetry={cancel.retry}
      />
      <AtoReasonDialog
        open={dialog === 'rollback'}
        onOpenChange={(open) => setDialog(open ? 'rollback' : null)}
        title={`Roll back “${label}”?`}
        description="The restriction is lifted at once (SMTP adapters stop enforcing it within seconds)."
        confirmLabel="Roll back"
        destructive
        pending={rollback.isPending}
        onSubmit={(reason) => rollback.submit({ path, body: { reason: reason ?? '' } })}
        onRetry={rollback.retry}
      />
    </div>
  );
}

export interface RequestPreset {
  actionType: AtoActionType;
  target?: AtoRequestBody['target'];
  /** Step 8.5: provider parameters (one mailbox item for `remove_forwarding_rule`). */
  params?: AtoRequestBody['params'];
  /** What the preset item is (shown in the dialog, e.g. "Inbox rule forwarding to example.net"). */
  subject?: string;
}

/**
 * "Request a response" for an ATO incident (§5.1 #16): the gateway actions of 8.4 for the account
 * kind, target scope (connector, connector + IP range), duration and mode for restrictions, the
 * manual description, and a reason. Medium and high impact go to `pending_approval` (or run when
 * the tenant's automation allows); the api answers with the action's state.
 */
export function RequestResponseButton({
  incidentId,
  accountKind,
  preset,
  label = 'Request a response',
  variant = 'outline',
}: {
  incidentId: string;
  accountKind: AtoAccountKind;
  preset?: RequestPreset;
  label?: string;
  variant?: 'outline' | 'default';
}) {
  const can = useCan('AtoResponsesController_request_v1');
  const [open, setOpen] = useState(false);
  const actions = REQUESTABLE_ACTIONS.filter((a) => a.kinds.includes(accountKind));
  const initial = preset?.actionType ?? actions[0]?.type ?? 'alert_tenant_admins';
  const [actionType, setActionType] = useState<AtoActionType>(initial);
  const [scope, setScope] = useState<string>(preset?.target?.scope ?? '');
  const [cidr, setCidr] = useState(preset?.target?.cidr ?? '');
  const [duration, setDuration] = useState(240);
  const [mode, setMode] = useState<'reject' | 'defer'>('reject');
  const [description, setDescription] = useState('');
  const typeId = useId();
  const scopeId = useId();
  const cidrId = useId();
  const durationId = useId();
  const modeId = useId();
  const descriptionId = useId();
  const mutation = useApiMutation('AtoResponsesController_request_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Response requested',
  });
  if (!can) return null;
  const action = REQUESTABLE_ACTIONS.find((a) => a.type === actionType);
  const connectorScopes = accountKind === 'smtp_connector' && action?.needsDuration;
  const manual = actionType === 'record_manual_action';
  const descriptionOk = !manual || description.trim().length >= 10;
  const cidrOk = scope !== 'connector_ip' || cidr.trim().length >= 3;
  const body = (reason: string): AtoRequestBody => ({
    actionType,
    reason,
    // The default target is the account itself (mailbox or connector); an IP range narrows a
    // connector authentication block (D14 `connector_ip`).
    ...(connectorScopes && scope === 'connector_ip'
      ? {
          target: {
            scope: 'connector_ip' as const,
            ...(preset?.target?.connectorId ? { connectorId: preset.target.connectorId } : {}),
            cidr: cidr.trim(),
          },
        }
      : {}),
    ...(action?.needsDuration ? { durationMinutes: duration } : {}),
    ...(action?.type === 'restrict_smtp_sending' ? { mode } : {}),
    ...(manual ? { description: description.trim() } : {}),
    // A preset mailbox item applies only to the preset's own action type.
    ...(preset?.params && actionType === preset.actionType ? { params: preset.params } : {}),
  });
  return (
    <>
      <Button size="sm" variant={variant} onClick={() => setOpen(true)}>
        {label}
      </Button>
      <AtoReasonDialog
        open={open}
        onOpenChange={setOpen}
        title="Request a response"
        description={
          <span className="grid gap-1">
            <span>
              {action && action.impact !== 'low'
                ? 'This is a high-impact response: it needs the approval of a second analyst (with MFA) unless the tenant’s automation allows it.'
                : 'Low-impact responses run at once.'}
            </span>
            {action?.provider ? (
              <span>
                The identity provider carries it out; it counts as done only when the provider
                confirms it.
                {actionType === 'remove_forwarding_rule' &&
                !(preset?.params?.itemId && preset.actionType === actionType)
                  ? ' Without a selected item it removes every forwarding to an external domain.'
                  : ''}
                {actionType === 'revoke_sessions'
                  ? ' Users sign in and authorize their applications again.'
                  : ''}
              </span>
            ) : null}
            {preset?.subject && preset.actionType === actionType ? (
              <span>Item: {preset.subject}</span>
            ) : null}
          </span>
        }
        confirmLabel="Request"
        disabled={!descriptionOk || !cidrOk}
        pending={mutation.isPending}
        extra={
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor={typeId}>Response</Label>
              <Select value={actionType} onValueChange={(v) => setActionType(v as AtoActionType)}>
                <SelectTrigger id={typeId}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {actions.map((a) => (
                    <SelectItem key={a.type} value={a.type}>
                      {ACTION_LABELS[a.type]} ({a.impact} impact)
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {connectorScopes ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="grid gap-1.5">
                  <Label htmlFor={scopeId}>Target</Label>
                  <Select value={scope || 'connector'} onValueChange={setScope}>
                    <SelectTrigger id={scopeId}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="connector">The whole connector</SelectItem>
                      {actionType === 'block_smtp_auth' ? (
                        <SelectItem value="connector_ip">The connector from an IP range</SelectItem>
                      ) : null}
                    </SelectContent>
                  </Select>
                </div>
                {scope === 'connector_ip' ? (
                  <div className="grid gap-1.5">
                    <Label htmlFor={cidrId}>IP range (CIDR)</Label>
                    <Input
                      id={cidrId}
                      value={cidr}
                      onChange={(e) => setCidr(e.target.value)}
                      placeholder="203.0.113.0/24"
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </div>
                ) : null}
              </div>
            ) : null}
            {action?.needsDuration ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="grid gap-1.5">
                  <Label htmlFor={durationId}>Duration</Label>
                  <Select value={String(duration)} onValueChange={(v) => setDuration(Number(v))}>
                    <SelectTrigger id={durationId}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {DURATION_OPTIONS.map((o) => (
                        <SelectItem key={o.value} value={String(o.value)}>
                          {o.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {action.type === 'restrict_smtp_sending' ? (
                  <div className="grid gap-1.5">
                    <Label htmlFor={modeId}>When restricted</Label>
                    <Select value={mode} onValueChange={(v) => setMode(v as 'reject' | 'defer')}>
                      <SelectTrigger id={modeId}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="reject">Reject new submissions (5.7.1)</SelectItem>
                        <SelectItem value="defer">Defer (4.7.1, queued by the sender)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                ) : null}
              </div>
            ) : null}
            {manual ? (
              <div className="grid gap-1.5">
                <Label htmlFor={descriptionId}>
                  What was done (required, at least 10 characters)
                </Label>
                <Textarea
                  id={descriptionId}
                  rows={2}
                  maxLength={1000}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
            ) : null}
          </div>
        }
        onSubmit={(reason) => mutation.submit({ path: { incidentId }, body: body(reason ?? '') })}
        onRetry={mutation.retry}
      />
    </>
  );
}
