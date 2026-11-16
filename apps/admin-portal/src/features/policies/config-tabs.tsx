'use client';

import Link from 'next/link';
import { DateTime } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiQuery } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import { CodeList, YesNo } from '@/features/messages/controls';

/**
 * The scanning tab of page 13 (read-only summary; editing lives in Settings → Scanning). The
 * policy settings and risk tabs moved to `settings-tab.tsx` and `risk/risk-tab.tsx` (step 7.3).
 */

type ScanSetting = ListItem<'ScanSettingsController_list_v1'>;

/** Scan settings summary (`GET /scan-settings`); editing lives in Settings → Scanning. */
export function ScanningTab() {
  const settings = useApiQuery('ScanSettingsController_list_v1');
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Per-engine thresholds and options; tenant overrides stay within platform bounds.
        </p>
        <Button asChild variant="outline" size="sm">
          <Link href="/settings?tab=scanning">Open scan settings</Link>
        </Button>
      </div>
      {settings.isLoading ? (
        <LoadingState label="Loading scan settings" rows={6} variant="table" />
      ) : settings.error ? (
        <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />
      ) : (settings.data?.data.length ?? 0) === 0 ? (
        <EmptyState title="No scan engines reported" />
      ) : (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <table className="w-full text-sm">
            <caption className="sr-only">Scan engines</caption>
            <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
              <tr>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Engine
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Required
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Tenant may disable
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Tenant override
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Violations
                </th>
                <th scope="col" className="px-3 py-2 font-semibold">
                  Updated
                </th>
              </tr>
            </thead>
            <tbody>
              {settings.data?.data.map((engine: ScanSetting) => (
                <tr key={engine.engine} className="border-t">
                  <th scope="row" className="px-3 py-2 text-left font-medium">
                    {humanize(engine.engine)}
                  </th>
                  <td className="px-3 py-2">
                    <YesNo value={engine.required} />
                  </td>
                  <td className="px-3 py-2">
                    <YesNo value={engine.tenantMayDisable} />
                  </td>
                  <td className="px-3 py-2">
                    {engine.overrideApplied
                      ? `Applied (version ${engine.version})`
                      : 'Platform defaults'}
                  </td>
                  <td className="px-3 py-2">
                    <CodeList codes={engine.violations.map((v) => `${v.path}: ${v.code}`)} />
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    <DateTime value={engine.updatedAt} emptyLabel="Never" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {settings.data?.note ? (
        <p className="text-xs text-muted-foreground">{settings.data.note}</p>
      ) : null}
    </div>
  );
}
