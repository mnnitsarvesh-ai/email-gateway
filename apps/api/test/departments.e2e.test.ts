/**
 * Step 5.2 department routes (P5, P22) over HTTP with the dependencies stubbed (see
 * support/policy-app.ts): `user:read` reads and `user:manage` writes, name uniqueness, members as
 * a normalized address in an active domain of the organization or a user of the organization,
 * bounds, `409 department_in_use` while an active policy version references the department,
 * isolation between two organizations and audit rows with ids only.
 */
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPolicyApp, type PolicyApp, roleOf } from './support/policy-app';
import { departmentExceptionDefinition } from './support/policy-fixtures';

const READ_ONLY = roleOf('read_only_user');
const ADMIN = roleOf('organization_admin');
const D = '/api/v1/departments';

describe('step 5.2 department routes (e2e, dependencies stubbed)', () => {
  let ctx: PolicyApp;
  const http = () => ctx.http();

  beforeAll(async () => {
    ctx = await createPolicyApp({ DEPARTMENT_MAX_PER_ORG: '10', DEPARTMENT_MAX_MEMBERS: '100' });
  });
  afterAll(async () => {
    await ctx?.close();
  });
  beforeEach(() => ctx.reset());

  it('answers 401 without credentials on every route', async () => {
    const id = randomUUID();
    await http().get(D).expect(401);
    await http().post(D).send({}).expect(401);
    await http().get(`${D}/${id}`).expect(401);
    await http().patch(`${D}/${id}`).send({}).expect(401);
    await http().delete(`${D}/${id}`).expect(401);
    await http().get(`${D}/${id}/members`).expect(401);
    await http().post(`${D}/${id}/members`).send({}).expect(401);
    await http().delete(`${D}/${id}/members/${id}`).expect(401);
  });

  it('manages departments and members under user:read / user:manage', async () => {
    await http()
      .post(D)
      .set(await ctx.as(READ_ONLY))
      .send({ name: 'Finance' })
      .expect(403);
    await http()
      .post(D)
      .set(await ctx.as(roleOf('security_analyst')))
      .send({ name: 'Finance' })
      .expect(403);
    const created = await http()
      .post(D)
      .set(await ctx.as(ADMIN))
      .send({ name: 'Finance' })
      .expect(201);
    expect(created.body).toMatchObject({ name: 'Finance', memberCount: 0, rowVersion: 1 });
    const id = created.body.id as string;
    const dup = await http()
      .post(D)
      .set(await ctx.as(ADMIN))
      .send({ name: 'Finance' })
      .expect(409);
    expect(dup.body.code).toBe('department_name_taken');

    const member = await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN))
      .send({ address: 'Alice@ACME.example' })
      .expect(201);
    expect(member.body).toMatchObject({
      kind: 'address',
      address: 'alice@acme.example',
      departmentId: id,
    });
    const notTenant = await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN))
      .send({ address: 'eve@evil.example' })
      .expect(400);
    expect(notTenant.body.code).toBe('member_address_not_tenant');
    const user = await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN))
      .send({ userId: ctx.store().users.get(10n)!.publicId })
      .expect(201);
    expect(user.body).toMatchObject({ kind: 'user', address: null });
    const foreignUser = ctx.store().addUser(77n, { organizationId: 2n });
    const notUser = await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN))
      .send({ userId: foreignUser.publicId })
      .expect(400);
    expect(notUser.body.code).toBe('member_user_not_tenant');
    await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN))
      .send({ address: 'a@acme.example', userId: foreignUser.publicId })
      .expect(400);
    const exists = await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN))
      .send({ address: 'alice@acme.example' })
      .expect(409);
    expect(exists.body.code).toBe('department_member_exists');

    const members = await http()
      .get(`${D}/${id}/members`)
      .set(await ctx.as(READ_ONLY))
      .expect(200);
    expect(members.body.data).toHaveLength(2);
    expect(
      (
        await http()
          .get(D)
          .set(await ctx.as(READ_ONLY))
          .expect(200)
      ).body.data[0].memberCount,
    ).toBe(2);
    await http()
      .delete(`${D}/${id}/members/${member.body.id as string}`)
      .set(await ctx.as(ADMIN))
      .expect(204);
    const conflict = await http()
      .patch(`${D}/${id}`)
      .set(await ctx.as(ADMIN))
      .send({ name: 'Finance EU', expectedRowVersion: 7 })
      .expect(409);
    expect(conflict.body).toMatchObject({ code: 'department_conflict', currentRowVersion: 1 });
    await http()
      .patch(`${D}/${id}`)
      .set(await ctx.as(ADMIN))
      .send({ name: 'Finance EU', expectedRowVersion: 1 })
      .expect(200);

    // Isolation: another organization never sees or changes it.
    await http()
      .get(`${D}/${id}`)
      .set(await ctx.as(ADMIN, 'B'))
      .expect(404);
    await http()
      .delete(`${D}/${id}`)
      .set(await ctx.as(ADMIN, 'B'))
      .expect(404);
    await http()
      .post(`${D}/${id}/members`)
      .set(await ctx.as(ADMIN, 'B'))
      .send({ address: 'x@acme.example' })
      .expect(404);

    // In use by an active policy version → 409; after disabling the policy it can go.
    const policy = await http()
      .post('/api/v1/policies')
      .set(await ctx.as(ADMIN))
      .send({ name: 'Finance exception', definition: departmentExceptionDefinition(id) })
      .expect(201);
    const pid = policy.body.policy.id as string;
    await http()
      .post(`/api/v1/policies/${pid}/versions/1/publish`)
      .set(await ctx.as(ADMIN))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    const inUse = await http()
      .delete(`${D}/${id}`)
      .set(await ctx.as(ADMIN))
      .expect(409);
    expect(inUse.body).toMatchObject({ code: 'department_in_use', policies: [{ policyId: pid }] });
    await http()
      .post(`/api/v1/policies/${pid}/disable`)
      .set(await ctx.as(ADMIN))
      .send({})
      .expect(200);
    await http()
      .delete(`${D}/${id}`)
      .set(await ctx.as(ADMIN))
      .expect(204);
    expect(ctx.store().memberRows).toHaveLength(0);

    const departmentActions = ctx.actions().filter((a) => a.startsWith('department.'));
    expect(departmentActions).toEqual([
      'department.created',
      'department.member_added',
      'department.member_added',
      'department.member_removed',
      'department.updated',
      'department.deleted',
    ]);
    const metadata = JSON.stringify(
      ctx.audit.record.mock.calls.map(([e]) => (e as { metadata: unknown }).metadata),
      (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    );
    expect(metadata).not.toContain('alice@');
  });

  it('caps departments per organization', async () => {
    for (let i = 0; i < 10; i += 1) {
      await http()
        .post(D)
        .set(await ctx.as(ADMIN))
        .send({ name: `d${i}` })
        .expect(201);
    }
    const capped = await http()
      .post(D)
      .set(await ctx.as(ADMIN))
      .send({ name: 'd10' })
      .expect(409);
    expect(capped.body).toMatchObject({ code: 'department_limit_reached', limit: 10 });
    await http()
      .post(D)
      .set(await ctx.as(ADMIN))
      .send({ name: '' })
      .expect(400);
  });
});
