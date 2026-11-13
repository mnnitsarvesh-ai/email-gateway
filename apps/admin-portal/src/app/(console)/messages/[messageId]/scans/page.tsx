import { ScanDetails } from '@/features/messages';

/** Security scan details (design §1.3 row 11). */
export default async function MessageScansPage({
  params,
}: {
  params: Promise<{ messageId: string }>;
}) {
  const { messageId } = await params;
  return <ScanDetails messageId={messageId} />;
}
