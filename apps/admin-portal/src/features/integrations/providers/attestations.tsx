'use client';

import { DateTime } from '@/components/domain/date-time';
import { Checkbox } from '@/components/ui/checkbox';
import { useApiMutation } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { MutationError } from '@/features/domains/kit';
import { CONNECTION_QUERIES } from './mail-flow-dialog';
import type { CatalogAttestation, Connection } from './model';

/**
 * Attestations of customer-side steps (D13, ADR-0080): statements by the administrator about
 * changes the gateway cannot observe with read-only access. Labelled as statements, never as
 * checks; recording one is audited (`integration.attestation_recorded`).
 */
export function Attestations({
  connection,
  attestations,
  phases,
}: {
  connection: Pick<Connection, 'id' | 'attestations' | 'status'>;
  attestations: readonly CatalogAttestation[];
  phases: readonly string[];
}) {
  const canRecord = useCan('ProviderAttestationsController_record_v1');
  const record = useApiMutation('ProviderAttestationsController_record_v1', {
    invalidates: CONNECTION_QUERIES,
    successMessage: 'Statement recorded.',
  });
  const shown = attestations.filter((a) => phases.includes(a.phase));
  if (shown.length === 0) return null;
  const disabled = !canRecord || record.isPending || connection.status === 'disabled';
  return (
    <fieldset className="grid gap-2 rounded-md border p-3">
      <legend className="px-1 text-sm font-medium">
        Your statements (customer-side steps the gateway cannot check)
      </legend>
      {shown.map((a) => {
        const recorded = connection.attestations.find((x) => x.code === a.code);
        const id = `attest-${a.code}`;
        return (
          <div key={a.code} className="flex items-start gap-2 text-sm">
            <Checkbox
              id={id}
              checked={Boolean(recorded)}
              disabled={disabled}
              onCheckedChange={(checked) =>
                void record.submit({
                  path: { id: connection.id },
                  body: { code: a.code, attested: checked === true },
                })
              }
            />
            <label htmlFor={id} className="grid gap-0.5 leading-snug">
              <span>{a.statement}</span>
              <span className="text-xs text-muted-foreground">
                {recorded ? (
                  <>
                    Stated <DateTime value={recorded.at} /> (your statement, not a gateway check)
                  </>
                ) : a.requiredFor ? (
                  `Required for the ${a.requiredFor} step`
                ) : (
                  'Recommended'
                )}
              </span>
            </label>
          </div>
        );
      })}
      <MutationError error={record.error} />
    </fieldset>
  );
}
