import { QuarantinePage } from '@/features/quarantine';

/** My quarantine (design §3.1; linked from quarantine digests). */
export default function QuarantineSelfRoute() {
  return <QuarantinePage routeTab="me" />;
}
