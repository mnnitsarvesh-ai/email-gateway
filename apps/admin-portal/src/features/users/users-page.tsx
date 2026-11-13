'use client';

import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { DepartmentsTab } from './departments-tab';
import { UsersTab } from './users-tab';

const URL_SHAPE = { tab: z.enum(['users', 'departments']).default('users').catch('users') };

/** `/users` (`?tab=users|departments`). */
export function UsersPage() {
  return (
    <RouteGate gate={['UsersController_list_v1']}>
      <Users />
    </RouteGate>
  );
}

function Users() {
  const [state, setState] = useUrlState(URL_SHAPE);
  const canDepartments = useCan('DepartmentsController_list_v1');
  const tab = canDepartments ? state.tab : 'users';
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Users"
        description="The people of your organization, their roles, status and sessions, and the departments policies refer to."
      />
      <Tabs
        value={tab}
        onValueChange={(value) =>
          setState({ tab: value as 'users' | 'departments' }, { push: true })
        }
      >
        <TabsList aria-label="Directory sections">
          <TabsTrigger value="users">Users</TabsTrigger>
          {canDepartments ? <TabsTrigger value="departments">Departments</TabsTrigger> : null}
        </TabsList>
        <TabsContent value="users" className="min-w-0">
          {tab === 'users' ? <UsersTab /> : null}
        </TabsContent>
        {canDepartments ? (
          <TabsContent value="departments" className="min-w-0">
            {tab === 'departments' ? <DepartmentsTab /> : null}
          </TabsContent>
        ) : null}
      </Tabs>
    </div>
  );
}
