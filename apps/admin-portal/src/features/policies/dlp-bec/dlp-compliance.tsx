'use client';

import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DateTime, UntrustedText } from '@/components/domain';
import { useZodForm } from '@/components/form';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Form } from '@/components/ui/form';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { OperationId } from '@/lib/api/types';
import { useCan, useMe } from '@/lib/auth/me';
import { formatUtc, humanize } from '@/lib/format';
import { DetailList, Section, YesNo } from '@/features/messages/controls';
import { aadhaarBody, aadhaarDefaults, aadhaarSchema, type AadhaarInput } from './dlp-schemas';
import { applyServerError, confirmProblem, type FieldRule, type Problem } from './errors';
import {
  CheckboxField,
  EditorSheet,
  FormAlert,
  MfaRequiredNotice,
  SelectField,
  SubmitRow,
  TextField,
} from './kit';
import { AADHAAR_BASES, AADHAAR_BASIS_LABELS, type DlpCompliance } from './model';

/**
 * The Aadhaar detection compliance basis (step 4.5 D17, ADR-0038): `dlp:compliance_manage`
 * (organization admin, super admin), `@RequireMfa()` and `@UserOnly()`, Idempotency-Key required
 * (both writes are `x-eg-idempotency: legacy`; `useApiMutation` sends one key per intent). A
 * session without MFA sees the MFA-required state instead of the actions.
 */

const COMPLIANCE_QUERIES: readonly OperationId[] = ['DlpComplianceController_get_v1'];

const AADHAAR_FIELDS: readonly FieldRule<keyof AadhaarInput>[] = [
  { path: 'basis', field: 'basis' },
  { path: 'reference', field: 'reference' },
  { path: 'reviewDueAt', field: 'reviewOn' },
  { path: 'attested', field: 'attested' },
];

export const RECORD_EXPLANATION =
  'Aadhaar numbers are detected (detector NI2) in messages scanned after the DLP engine’s cache refresh (30 seconds by default), until the review date. They are stored masked (last four digits) only, even inside evidence. Recording is audited with your attestation; whether the basis is lawful is your organization’s decision.';

export const WITHDRAW_EXPLANATION =
  'The recorded basis is cleared and the Aadhaar detector stops running for messages scanned after the DLP engine’s cache refresh (30 seconds by default). Rules that select NI2 stay but find nothing; finished scans keep their result. The withdrawal is audited.';

function RecordBasisForm({
  compliance,
  onDone,
  onReload,
}: {
  compliance: DlpCompliance;
  onDone: () => void;
  onReload: () => void;
}) {
  const [problem, setProblem] = useState<Problem | null>(null);
  const [confirming, setConfirming] = useState<AadhaarInput | null>(null);
  const record = useApiMutation('DlpComplianceController_enable_v1', {
    invalidates: COMPLIANCE_QUERIES,
    successMessage: 'Aadhaar detection basis recorded.',
  });
  const form = useZodForm(aadhaarSchema, { defaultValues: aadhaarDefaults(compliance.aadhaar) });
  const submit = form.handleSubmit((values) => {
    setProblem(null);
    setConfirming(values);
  });
  return (
    <Form {...form}>
      <form
        className="grid min-w-0 gap-4 [&>*]:min-w-0"
        noValidate
        aria-label="Record the Aadhaar detection basis"
        onSubmit={(event) => void submit(event)}
      >
        <FormAlert problem={problem} onReload={onReload} />
        <SelectField
          control={form.control}
          name="basis"
          label="Basis"
          required
          options={AADHAAR_BASES.map((value) => ({ value, label: AADHAAR_BASIS_LABELS[value] }))}
        />
        <TextField
          control={form.control}
          name="reference"
          label="Document or approval reference"
          required
          maxLength={256}
          hint="Your organization's reference for the basis, such as a policy number or approval ID."
        />
        <TextField
          control={form.control}
          name="reviewOn"
          label="Review date"
          type="date"
          required
          hint="At most 365 days ahead; detection stops after the end of this day (UTC) until the basis is recorded again."
        />
        <CheckboxField
          control={form.control}
          name="attested"
          label="I attest that my organization holds this basis for detecting Aadhaar numbers."
        />
        <SubmitRow
          label="Record basis"
          pending={record.isPending}
          retryAfterSeconds={record.retryAfterSeconds}
          onCancel={onDone}
        />
      </form>
      <ConfirmDialog
        open={confirming !== null}
        onOpenChange={(open) => !open && setConfirming(null)}
        title="Record the Aadhaar detection basis?"
        description={
          <div className="grid gap-2">
            <p>{RECORD_EXPLANATION}</p>
            {confirming ? (
              <p>
                Basis: {AADHAAR_BASIS_LABELS[confirming.basis]}. Review date:{' '}
                {formatUtc(`${confirming.reviewOn}T23:59:59.000Z`)}.
              </p>
            ) : null}
          </div>
        }
        confirmLabel="Record basis"
        onConfirm={async () => {
          if (!confirming) return false;
          const outcome = await record.submit({
            body: aadhaarBody(compliance.version, confirming),
          });
          if (outcome.ok) {
            onDone();
            return true;
          }
          setProblem(applyServerError(form, outcome.error, AADHAAR_FIELDS));
          return true;
        }}
      />
    </Form>
  );
}

/** The "Compliance" section of the DLP tab. */
export function DlpComplianceSection() {
  const compliance = useApiQuery('DlpComplianceController_get_v1');
  const canRecord = useCan('DlpComplianceController_enable_v1');
  const canWithdraw = useCan('DlpComplianceController_disable_v1');
  const me = useMe();
  const mfa = me.data?.session.mfaAuthenticated === true;
  // The record form works on the settings loaded when it opened (see `refetchEntry`).
  const [recording, setRecording] = useState<DlpCompliance | null>(null);
  const [withdrawing, setWithdrawing] = useState(false);
  const withdraw = useApiMutation('DlpComplianceController_disable_v1', {
    invalidates: COMPLIANCE_QUERIES,
    successMessage: 'Aadhaar detection basis withdrawn.',
  });
  if (compliance.isLoading) return <LoadingState label="Loading compliance status" rows={4} />;
  if (compliance.error || !compliance.data) {
    return <ErrorState error={compliance.error} onRetry={() => void compliance.refetch()} />;
  }
  const data = compliance.data;
  const a = data.aadhaar;
  const manage = canRecord || canWithdraw;
  return (
    <Section
      title="Aadhaar detection"
      description="Aadhaar numbers are detected only with a recorded legal basis."
      actions={
        manage && mfa ? (
          <>
            {canRecord ? (
              <Button size="sm" onClick={() => setRecording(data)}>
                {a.enabled ? 'Update basis' : 'Record basis'}
              </Button>
            ) : null}
            {canWithdraw && a.enabled ? (
              <Button size="sm" variant="outline" onClick={() => setWithdrawing(true)}>
                Withdraw basis
              </Button>
            ) : null}
          </>
        ) : null
      }
    >
      <DetailList
        items={[
          { label: 'Enabled', value: <YesNo value={a.enabled} /> },
          { label: 'Active', value: <YesNo value={a.active} /> },
          {
            label: 'Legal basis',
            value: a.basis ? (
              (AADHAAR_BASIS_LABELS[a.basis] ?? humanize(a.basis))
            ) : (
              <span className="text-muted-foreground">None recorded</span>
            ),
          },
          { label: 'Reference', value: <UntrustedText value={a.reference} emptyLabel="None" /> },
          { label: 'Attested', value: <YesNo value={a.attested} /> },
          {
            label: 'Recorded',
            value: <DateTime value={a.recordedAt} mode="absolute" emptyLabel="Never" />,
          },
          {
            label: 'Review due',
            value: <DateTime value={a.reviewDueAt} mode="absolute" emptyLabel="Not set" />,
          },
        ]}
      />
      {manage && !mfa ? (
        <MfaRequiredNotice action="Recording or withdrawing the Aadhaar detection basis" />
      ) : null}
      <EditorSheet
        open={recording !== null}
        onOpenChange={(open) => !open && setRecording(null)}
        title={
          recording?.aadhaar.enabled
            ? 'Update the Aadhaar detection basis'
            : 'Record the Aadhaar detection basis'
        }
        description={RECORD_EXPLANATION}
      >
        {recording ? (
          <RecordBasisForm
            key={recording.version}
            compliance={recording}
            onDone={() => setRecording(null)}
            onReload={() =>
              void compliance.refetch().then((result) => {
                if (result.data) setRecording(result.data);
              })
            }
          />
        ) : null}
      </EditorSheet>
      <ConfirmDialog
        open={withdrawing}
        onOpenChange={(open) => {
          if (!open) {
            setWithdrawing(false);
            withdraw.reset();
          }
        }}
        title="Withdraw the Aadhaar detection basis?"
        description={<p>{WITHDRAW_EXPLANATION}</p>}
        confirmLabel="Withdraw basis"
        destructive
        error={<FormAlert problem={withdraw.error ? confirmProblem(withdraw.error) : null} />}
        onConfirm={async () => {
          const outcome = await withdraw.submit({ query: { expectedVersion: data.version } });
          if (!outcome.ok && outcome.error.code === 'version_conflict') {
            void compliance.refetch();
          }
          return outcome.ok;
        }}
      />
    </Section>
  );
}
