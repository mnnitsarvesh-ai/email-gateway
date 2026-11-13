import { ApprovalDetail } from '@/features/quarantine';

/** Approval request (design §3.1; linked from approval e-mails). */
export default async function QuarantineApprovalRoute({
  params,
}: {
  params: Promise<{ approvalId: string }>;
}) {
  const { approvalId } = await params;
  return <ApprovalDetail approvalId={approvalId} />;
}
