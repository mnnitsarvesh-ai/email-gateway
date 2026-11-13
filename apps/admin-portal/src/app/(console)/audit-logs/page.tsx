import { Suspense } from 'react';
import { AuditLogsPage } from '@/features/audit/audit-logs-page';

export default function Page() {
  return (
    <Suspense>
      <AuditLogsPage />
    </Suspense>
  );
}
