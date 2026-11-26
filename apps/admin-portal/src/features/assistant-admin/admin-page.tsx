'use client';

import Link from 'next/link';
import { useCallback } from 'react';
import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { navGate } from '@/features/reports/nav-gate';
import { useUrlState } from '@/hooks/use-url-state';
import { usePermissions } from '@/lib/auth/me';
import { canPerform } from '@/lib/auth/permissions';
import { RouteGate } from '@/lib/auth/route-gate';
import { AuditConversationDrawer } from './audit-detail';
import { AuditTab } from './audit-tab';
import { ExecutionsTab } from './executions-tab';
import { FeedbackTab } from './feedback-tab';
import { LimitsTab } from './limits-tab';
import { ADMIN_TABS, ADMIN_TAB_GATE, ADMIN_TAB_LABEL, type AdminTab } from './model';
import { AdminRangeControl } from './range-control';
import { UsageTab } from './usage-tab';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const URL_SHAPE = {
  tab: z.enum(ADMIN_TABS).optional().catch(undefined),
  /** The conversation whose audit drawer is open. */
  audit: z.string().regex(UUID).optional().catch(undefined),
};

/** Tabs whose lists use the page's time range. */
const RANGED: ReadonlySet<AdminTab> = new Set(['usage', 'feedback', 'audit', 'executions']);

/**
 * `/assistant/admin` (step AI-6 D1): the tenant AI administration page. Usage, limits and
 * provider, and feedback need `assistant:configure`; the conversation audit and the tool-call
 * search need `audit:read` and show metadata only (I24). Each tab is gated by its operation.
 */
export function AssistantAdminPage() {
  return (
    <RouteGate gate={navGate('assistant-admin')}>
      <AssistantAdmin />
    </RouteGate>
  );
}

function AssistantAdmin() {
  const permissions = usePermissions();
  const [state, setState] = useUrlState(URL_SHAPE);
  const allowed = ADMIN_TABS.filter((tab) => canPerform(ADMIN_TAB_GATE[tab], permissions));
  const tab = state.tab && allowed.includes(state.tab) ? state.tab : allowed[0];
  const canAuditDetail = canPerform('AssistantAdminAuditController_conversation_v1', permissions);
  const openAudit = useCallback(
    (conversationId: string) => setState({ audit: conversationId }, { push: true }),
    [setState],
  );
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="AI administration"
        description="How your organization uses the AI assistant: usage and estimated cost per person, limits, data sharing, your own provider key, feedback on answers and an audit of conversations without their content."
      />
      {canPerform('AssistantSettingsController_get_v1', permissions) ? (
        <p className="-mt-3 text-sm text-muted-foreground">
          Turn the assistant on or off in{' '}
          <Link
            href="/settings?tab=assistant"
            className="text-primary underline underline-offset-4"
          >
            Settings → AI assistant
          </Link>
          .
        </p>
      ) : null}
      {tab ? (
        <Tabs
          value={tab}
          onValueChange={(value) => setState({ tab: value as AdminTab }, { push: true })}
        >
          <TabsList aria-label="AI administration sections" className="h-auto flex-wrap">
            {allowed.map((value) => (
              <TabsTrigger key={value} value={value}>
                {ADMIN_TAB_LABEL[value]}
              </TabsTrigger>
            ))}
          </TabsList>
          {RANGED.has(tab) ? <AdminRangeControl className="mt-4" /> : null}
          {allowed.map((value) => (
            <TabsContent key={value} value={value} className="mt-4 min-w-0">
              {tab === value ? (
                value === 'usage' ? (
                  <UsageTab />
                ) : value === 'limits' ? (
                  <LimitsTab />
                ) : value === 'feedback' ? (
                  <FeedbackTab onOpenConversation={canAuditDetail ? openAudit : undefined} />
                ) : value === 'audit' ? (
                  <AuditTab onOpen={openAudit} />
                ) : (
                  <ExecutionsTab onOpenConversation={openAudit} />
                )
              ) : null}
            </TabsContent>
          ))}
        </Tabs>
      ) : null}
      {canAuditDetail ? (
        <AuditConversationDrawer
          conversationId={state.audit ?? null}
          onClose={() => setState({ audit: undefined })}
        />
      ) : null}
    </div>
  );
}
