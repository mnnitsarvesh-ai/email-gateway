import { Suspense } from 'react';
import { ThreatIntelligencePage } from '@/features/threat-intel/threat-intelligence-page';

export default function Page() {
  return (
    <Suspense>
      <ThreatIntelligencePage />
    </Suspense>
  );
}
