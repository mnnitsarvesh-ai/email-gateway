import { ReleaseStatus } from '@/features/quarantine';

/** Release status (design §3.1; linked from release e-mails). */
export default async function QuarantineReleaseRoute({
  params,
}: {
  params: Promise<{ releaseId: string }>;
}) {
  const { releaseId } = await params;
  return <ReleaseStatus releaseId={releaseId} />;
}
