#!/usr/bin/env node
// RabbitMQ provisioning for topology v1 (step 3.2 Q5, Q10; ADR-0024). The only code that
// declares broker objects: services verify passively and their users cannot configure.
//
//   node init.mjs [--vhost <name>] [--mgmt-url <url>] [--definitions <path>]
//                 [--users] [--cleanup-legacy] [--legacy-vhost <name>]
//   node init.mjs --delete-vhost <name>            # test teardown; refuses email-gateway and /
//
// Plain Node 22 (ESM, global fetch, no dependencies) against the management HTTP API, as the
// administrator (RABBITMQ_USER / RABBITMQ_PASSWORD). Steps, all idempotent:
//   1. wait for the management API (up to 120 s);
//   2. create/update the vhost (description "email-gateway topology v<N>", default queue type
//      quorum) and grant the administrator full permissions on it;
//   3. import definitions.json (exchanges, quorum queues, bindings, policies) into the vhost;
//   4. --users: create/update the role users (no tags) with exactly their Q10 permissions and
//      their topic permissions (routing keys each user may publish per exchange; every other
//      topic permission of the user on the vhost is removed);
//   5. --cleanup-legacy: delete the ADR-0005 objects on vhost "/" only when empty (queues with
//      no messages and no consumers; RabbitMQ 4.x refuses `if-empty` deletes of quorum queues,
//      so emptiness is checked first); --legacy-vhost points it at another vhost (tests only);
//   6. verify: exactly the 6 exchanges and 14 quorum queues, every binding, every policy applied,
//      and (--users) each role user's permissions and topic permissions exactly.
// Exits non-zero on any failure. Logs object names and counts only: never a password, never a
// URL with credentials.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PROTECTED_VHOSTS = new Set(['email-gateway', '/']);
const WAIT_TIMEOUT_MS = 120_000;
const REQUEST_TIMEOUT_MS = 15_000;

const SIX = ['email.ingestion', 'email.security', 'email.policy', 'email.delivery', 'email.archive', 'email.events'];
const SIX_EXCHANGES = '^email\\.(ingestion|security|policy|delivery|archive|events)$';
/** Event keys `org.<organizationId>.<eventType>` (Q2): only the relay publishes them. */
const EVENT_KEYS = '^org\\.[1-9][0-9]{0,19}\\.';
/** A topic permission: the routing keys a user may publish to one topic exchange (no reads). */
const topic = (exchange, write) => ({ exchange, write, read: '^$' });
/**
 * Q10: role users, their environment keys, permissions on the vhost and topic permissions
 * (review round 1: the broker is a trust boundary for approvals, so each user may publish only
 * the routing keys of its role: the relay the event keys, a consumer the retry/delay/dead-letter
 * hops of its own queue, ops (dead-letter replay) the retry hops of the two replayable queues).
 */
const ROLE_USERS = [
  {
    role: 'relay',
    userKey: 'RABBITMQ_RELAY_USER',
    passwordKey: 'RABBITMQ_RELAY_PASSWORD',
    configure: '^$',
    write: SIX_EXCHANGES,
    read: '^$',
    topics: SIX.map((exchange) => topic(exchange, EVENT_KEYS)),
  },
  {
    role: 'email-worker',
    userKey: 'RABBITMQ_EMAIL_WORKER_USER',
    passwordKey: 'RABBITMQ_EMAIL_WORKER_PASSWORD',
    configure: '^$',
    write: '^email\\.(ingestion|events)$',
    read: '^email\\.received$',
    topics: [
      topic('email.ingestion', '^retry\\.email\\.received\\.'),
      topic('email.events', '^dead-letter\\.email\\.received(\\.|$)'),
    ],
  },
  {
    role: 'delivery-worker',
    userKey: 'RABBITMQ_DELIVERY_WORKER_USER',
    passwordKey: 'RABBITMQ_DELIVERY_WORKER_PASSWORD',
    configure: '^$',
    write: '^email\\.(delivery|events)$',
    read: '^email\\.delivery\\.pending$',
    topics: [
      topic('email.delivery', '^(retry|delay)\\.email\\.delivery\\.pending\\.'),
      topic('email.events', '^dead-letter\\.email\\.delivery\\.pending(\\.|$)'),
    ],
  },
  {
    role: 'ops',
    userKey: 'RABBITMQ_OPS_USER',
    passwordKey: 'RABBITMQ_OPS_PASSWORD',
    configure: '^$',
    // Replay republishes only to the home exchanges of the replayable work queues (Q9).
    write: '^email\\.(ingestion|delivery)$',
    read: '^email\\.dead-letter$',
    topics: [
      topic('email.ingestion', '^retry\\.email\\.received\\.'),
      topic('email.delivery', '^retry\\.email\\.delivery\\.pending\\.'),
    ],
  },
];

/** ADR-0005 objects on vhost "/" (removed by step 3.2). */
const LEGACY_QUEUES = [
  'email-worker.message-received',
  'policy-engine.message-scanned',
  'delivery-worker.policy-decided',
  'archive-worker.policy-decided',
  'notification-worker.events',
];
const LEGACY_EXCHANGES = ['mail.events', 'mail.dlx'];

class InitError extends Error {}

function log(message) {
  process.stdout.write(`rabbitmq-init: ${message}\n`);
}

function warn(message) {
  process.stderr.write(`rabbitmq-init: WARNING: ${message}\n`);
}

function parseArgs(argv) {
  const options = {
    vhost: undefined,
    mgmtUrl: undefined,
    definitions: fileURLToPath(new URL('./definitions.json', import.meta.url)),
    users: false,
    cleanupLegacy: false,
    legacyVhost: '/',
    deleteVhost: undefined,
  };
  const valueOf = (flag, index) => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new InitError(`${flag} needs a value`);
    return value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--vhost':
        options.vhost = valueOf(arg, i);
        i += 1;
        break;
      case '--mgmt-url':
        options.mgmtUrl = valueOf(arg, i);
        i += 1;
        break;
      case '--definitions':
        options.definitions = valueOf(arg, i);
        i += 1;
        break;
      case '--delete-vhost':
        options.deleteVhost = valueOf(arg, i);
        i += 1;
        break;
      case '--users':
        options.users = true;
        break;
      case '--cleanup-legacy':
        options.cleanupLegacy = true;
        break;
      case '--legacy-vhost':
        options.legacyVhost = valueOf(arg, i);
        i += 1;
        break;
      default:
        throw new InitError(`unknown argument ${JSON.stringify(arg)}`);
    }
  }
  return options;
}

function requireEnv(keys) {
  const missing = keys.filter((key) => !process.env[key]);
  if (missing.length > 0) throw new InitError(`missing environment: ${missing.join(', ')}`);
  return Object.fromEntries(keys.map((key) => [key, process.env[key]]));
}

/** The management API base URL without credentials (credentials go in the header only). */
function managementBase(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new InitError('the management URL is not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InitError('the management URL must be http(s)://');
  }
  url.username = '';
  url.password = '';
  url.pathname = url.pathname.replace(/\/+$/, '');
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/+$/, '');
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const enc = encodeURIComponent;

function createClient(base, user, password) {
  const authorization = `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
  return async function request(method, path, body, { allow = [] } = {}) {
    let response;
    try {
      response = await fetch(`${base}/api${path}`, {
        method,
        headers: {
          authorization,
          accept: 'application/json',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (error) {
      const code = error?.cause?.code ?? error?.name ?? 'network_error';
      throw new InitError(`${method} ${path}: management API unreachable (${code})`);
    }
    const text = await response.text();
    if (!response.ok && !allow.includes(response.status)) {
      let reason = '';
      try {
        const parsed = JSON.parse(text);
        reason = String(parsed.reason ?? parsed.error ?? '').slice(0, 300);
      } catch {
        // not JSON: the status is enough
      }
      throw new InitError(
        `${method} ${path}: HTTP ${response.status}${reason ? ` (${reason})` : ''}`,
      );
    }
    return { status: response.status, data: text ? safeJson(text) : undefined };
  };
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

async function waitForApi(request, displayBase) {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  let lastProblem = 'no response';
  for (let attempt = 1; ; attempt += 1) {
    try {
      const { status, data } = await request('GET', '/overview', undefined, {
        allow: [401, 403, 500, 502, 503],
      });
      if (status === 401 || status === 403) {
        throw new InitError('the administrator user was refused by the management API');
      }
      if (status === 200) {
        log(`management API ready at ${displayBase} (RabbitMQ ${data?.rabbitmq_version ?? '?'})`);
        return;
      }
      lastProblem = `HTTP ${status}`;
    } catch (error) {
      if (error instanceof InitError && /refused by/.test(error.message)) throw error;
      lastProblem = error instanceof Error ? error.message : String(error);
    }
    if (Date.now() >= deadline) {
      throw new InitError(`management API not ready after ${WAIT_TIMEOUT_MS / 1000} s: ${lastProblem}`);
    }
    if (attempt === 1) log(`waiting for the management API at ${displayBase}`);
    await sleep(2000);
  }
}

function loadDefinitions(path) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new InitError('definitions file is missing or not valid JSON');
  }
  const version = parsed.topology_version;
  if (!Number.isInteger(version) || version < 1) {
    throw new InitError('definitions file has no topology_version');
  }
  for (const key of ['exchanges', 'queues', 'bindings', 'policies']) {
    if (!Array.isArray(parsed[key])) throw new InitError(`definitions file has no ${key} array`);
  }
  return parsed;
}

/** The import body for `vhost`: no topology_version, every object's vhost set to the target. */
function importBody(definitions, vhost) {
  const withVhost = (items) => items.map((item) => ({ ...item, vhost }));
  return {
    exchanges: withVhost(definitions.exchanges),
    queues: withVhost(definitions.queues),
    bindings: withVhost(definitions.bindings),
    policies: withVhost(definitions.policies),
  };
}

async function deleteVhost(request, name) {
  if (PROTECTED_VHOSTS.has(name)) {
    throw new InitError(`refusing to delete the protected vhost ${JSON.stringify(name)}`);
  }
  const { status } = await request('DELETE', `/vhosts/${enc(name)}`, undefined, { allow: [404] });
  log(status === 404 ? `vhost ${name} does not exist` : `deleted vhost ${name}`);
}

async function ensureVhost(request, vhost, version, adminUser) {
  await request('PUT', `/vhosts/${enc(vhost)}`, {
    description: `email-gateway topology v${version}`,
    default_queue_type: 'quorum',
    tags: '',
  });
  await request('PUT', `/permissions/${enc(vhost)}/${enc(adminUser)}`, {
    configure: '.*',
    write: '.*',
    read: '.*',
  });
  log(`vhost ${vhost} ready (topology v${version}, default queue type quorum)`);
}

async function importDefinitions(request, vhost, definitions) {
  await request('POST', `/definitions/${enc(vhost)}`, importBody(definitions, vhost));
  log(
    `imported ${definitions.exchanges.length} exchanges, ${definitions.queues.length} queues, ` +
      `${definitions.bindings.length} bindings, ${definitions.policies.length} policies into ${vhost}`,
  );
}

async function ensureUsers(request, vhost) {
  const env = requireEnv(ROLE_USERS.flatMap((u) => [u.userKey, u.passwordKey]));
  for (const role of ROLE_USERS) {
    const name = env[role.userKey];
    await request('PUT', `/users/${enc(name)}`, { password: env[role.passwordKey], tags: '' });
    await request('PUT', `/permissions/${enc(vhost)}/${enc(name)}`, {
      configure: role.configure,
      write: role.write,
      read: role.read,
    });
    // Topic permissions: set the role's own (one per exchange, overwriting), then, only if the
    // user has one for another exchange, clear them all and set the role's again.
    const putTopics = async () => {
      for (const entry of role.topics) {
        await request('PUT', `/topic-permissions/${enc(vhost)}/${enc(name)}`, entry);
      }
    };
    await putTopics();
    const existing = await request('GET', `/topic-permissions/${enc(vhost)}/${enc(name)}`, undefined, {
      allow: [404],
    });
    const own = new Set(role.topics.map((t) => t.exchange));
    const entries = existing.status === 404 || !Array.isArray(existing.data) ? [] : existing.data;
    if (entries.some((t) => !own.has(t.exchange))) {
      await request('DELETE', `/topic-permissions/${enc(vhost)}/${enc(name)}`, undefined, {
        allow: [404],
      });
      await putTopics();
    }
    log(`user ${name} (${role.role}) ready on ${vhost} (${role.topics.length} topic permissions)`);
  }
  return ROLE_USERS.map((role) => ({ ...role, name: env[role.userKey] }));
}

async function cleanupLegacy(request, legacyVhost) {
  const root = enc(legacyVhost);
  const on = legacyVhost === '/' ? '/' : legacyVhost;
  for (const base of LEGACY_QUEUES) {
    for (const name of [base, `${base}.dlq`]) {
      const { status, data } = await request('GET', `/queues/${root}/${enc(name)}`, undefined, {
        allow: [404],
      });
      if (status === 404) continue;
      const messages = data?.messages;
      if (messages !== 0) {
        warn(
          `legacy queue ${name} on ${on} kept: ${messages === undefined ? 'message count unknown' : `${messages} messages`}`,
        );
        continue;
      }
      if ((data?.consumers ?? 0) !== 0) {
        warn(`legacy queue ${name} on ${on} kept: it has consumers`);
        continue;
      }
      // Classic queues: the broker re-checks emptiness atomically (`if-empty`). Quorum queues
      // (every ADR-0005 queue) refuse `if-empty` with 400 on RabbitMQ 4.x, so for them the
      // emptiness checked above is the guard; nothing publishes to the legacy exchanges any more
      // (step 3.2 removed every publisher), so no message can arrive in between.
      const quorum = data?.type === 'quorum';
      const result = await request(
        'DELETE',
        `/queues/${root}/${enc(name)}${quorum ? '' : '?if-empty=true'}`,
        undefined,
        { allow: [400, 404, 409] },
      );
      if (result.status === 204 || result.status === 200) {
        log(`deleted legacy queue ${name} on ${on}`);
      } else if (result.status !== 404) {
        warn(`legacy queue ${name} on ${on} kept: not empty (HTTP ${result.status})`);
      }
    }
  }
  for (const name of LEGACY_EXCHANGES) {
    const { status } = await request('GET', `/exchanges/${root}/${enc(name)}`, undefined, {
      allow: [404],
    });
    if (status === 404) continue;
    const result = await request(
      'DELETE',
      `/exchanges/${root}/${enc(name)}?if-unused=true`,
      undefined,
      { allow: [400, 404, 409] },
    );
    if (result.status === 204 || result.status === 200) log(`deleted legacy exchange ${name} on ${on}`);
    else if (result.status !== 404) warn(`legacy exchange ${name} on ${on} kept: still bound`);
  }
}

const sameDefinition = (a, b) => {
  const keys = new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})]);
  return [...keys].every((key) => a?.[key] === b?.[key]);
};
const bindingId = (b) => `${b.source} -> ${b.destination_type}:${b.destination} [${b.routing_key}]`;

async function verifyOnce(request, vhost, definitions, users) {
  const problems = [];
  const v = enc(vhost);

  const exchanges = (await request('GET', `/exchanges/${v}`)).data.filter(
    (e) => e.name !== '' && !e.name.startsWith('amq.'),
  );
  const expectedExchanges = new Set(definitions.exchanges.map((e) => e.name));
  for (const exchange of exchanges) {
    if (!expectedExchanges.has(exchange.name)) problems.push(`unexpected exchange ${exchange.name}`);
    else if (exchange.type !== 'topic' || exchange.durable !== true || exchange.internal) {
      problems.push(`exchange ${exchange.name} is not a durable, non-internal topic exchange`);
    }
  }
  for (const name of expectedExchanges) {
    if (!exchanges.some((e) => e.name === name)) problems.push(`missing exchange ${name}`);
  }

  const queues = (await request('GET', `/queues/${v}?columns=name,type,durable,policy`)).data;
  const expectedQueues = new Set(definitions.queues.map((q) => q.name));
  for (const queue of queues) {
    if (!expectedQueues.has(queue.name)) {
      problems.push(`unexpected queue ${queue.name}`);
      continue;
    }
    if (queue.type !== 'quorum' || queue.durable !== true) {
      problems.push(`queue ${queue.name} is not a durable quorum queue`);
    }
    if (queue.policy !== `eg.${queue.name}`) {
      problems.push(`queue ${queue.name} has policy ${queue.policy ?? 'none'}, expected eg.${queue.name}`);
    }
  }
  for (const name of expectedQueues) {
    if (!queues.some((q) => q.name === name)) problems.push(`missing queue ${name}`);
  }

  const bindings = (await request('GET', `/bindings/${v}`)).data.filter((b) => b.source !== '');
  const actualBindings = new Set(bindings.map(bindingId));
  const expectedBindings = new Set(definitions.bindings.map(bindingId));
  for (const id of expectedBindings) if (!actualBindings.has(id)) problems.push(`missing binding ${id}`);
  for (const id of actualBindings) if (!expectedBindings.has(id)) problems.push(`unexpected binding ${id}`);

  const policies = (await request('GET', `/policies/${v}`)).data;
  for (const expected of definitions.policies) {
    const actual = policies.find((p) => p.name === expected.name);
    if (!actual) problems.push(`missing policy ${expected.name}`);
    else if (
      actual.pattern !== expected.pattern ||
      actual['apply-to'] !== expected['apply-to'] ||
      actual.priority !== expected.priority ||
      !sameDefinition(actual.definition, expected.definition)
    ) {
      problems.push(`policy ${expected.name} differs from the definitions`);
    }
  }
  for (const policy of policies) {
    if (!definitions.policies.some((p) => p.name === policy.name)) {
      warn(`policy ${policy.name} on ${vhost} is not part of the definitions`);
    }
  }

  for (const user of users) {
    const { status, data } = await request('GET', `/users/${enc(user.name)}`, undefined, {
      allow: [404],
    });
    if (status === 404) {
      problems.push(`missing user ${user.name}`);
      continue;
    }
    const tags = Array.isArray(data.tags) ? data.tags : String(data.tags ?? '').split(',');
    if (tags.some((tag) => tag !== '')) problems.push(`user ${user.name} has tags`);
    const permission = await request('GET', `/permissions/${v}/${enc(user.name)}`, undefined, {
      allow: [404],
    });
    const p = permission.data;
    if (
      permission.status === 404 ||
      p.configure !== user.configure ||
      p.write !== user.write ||
      p.read !== user.read
    ) {
      problems.push(`user ${user.name} does not have exactly its permissions on ${vhost}`);
    }
    const topics = await request('GET', `/topic-permissions/${v}/${enc(user.name)}`, undefined, {
      allow: [404],
    });
    const actualTopics = topics.status === 404 || !Array.isArray(topics.data) ? [] : topics.data;
    const topicId = (t) => `${t.exchange} write=${t.write} read=${t.read}`;
    const expectedTopics = new Set(user.topics.map(topicId));
    const actualTopicIds = new Set(actualTopics.map(topicId));
    if (
      expectedTopics.size !== actualTopicIds.size ||
      [...expectedTopics].some((id) => !actualTopicIds.has(id))
    ) {
      problems.push(`user ${user.name} does not have exactly its topic permissions on ${vhost}`);
    }
  }

  return { problems, exchanges: exchanges.length, queues: queues.length, bindings: bindings.length };
}

async function verify(request, vhost, definitions, users) {
  // Policies are applied asynchronously after the import; give them a few seconds.
  let result;
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    result = await verifyOnce(request, vhost, definitions, users);
    if (result.problems.length === 0) break;
    await sleep(1000);
  }
  if (result.problems.length > 0) {
    throw new InitError(
      `verification of ${vhost} failed:\n${result.problems.map((p) => `  - ${p}`).join('\n')}`,
    );
  }
  log(
    `verified ${vhost}: ${result.exchanges} exchanges, ${result.queues} quorum queues with policies, ` +
      `${result.bindings} bindings${users.length > 0 ? `, ${users.length} role users` : ''}`,
  );
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const { RABBITMQ_USER: adminUser, RABBITMQ_PASSWORD: adminPassword } = requireEnv([
    'RABBITMQ_USER',
    'RABBITMQ_PASSWORD',
  ]);
  const base = managementBase(
    options.mgmtUrl ?? (process.env.RABBITMQ_MGMT_URL || 'http://rabbitmq:15672'),
  );
  const request = createClient(base, adminUser, adminPassword);
  await waitForApi(request, base);

  if (options.deleteVhost !== undefined) {
    await deleteVhost(request, options.deleteVhost);
    return;
  }

  const vhost = options.vhost ?? (process.env.RABBITMQ_VHOST || 'email-gateway');
  if (vhost === '/') throw new InitError('topology v1 is never provisioned on vhost "/"');
  const definitions = loadDefinitions(options.definitions);
  await ensureVhost(request, vhost, definitions.topology_version, adminUser);
  await importDefinitions(request, vhost, definitions);
  const users = options.users ? await ensureUsers(request, vhost) : [];
  if (options.cleanupLegacy) await cleanupLegacy(request, options.legacyVhost);
  await verify(request, vhost, definitions, users);
}

main().catch((error) => {
  const message = error instanceof InitError ? error.message : 'unexpected failure';
  process.stderr.write(`rabbitmq-init: FAILED: ${message}\n`);
  if (!(error instanceof InitError) && error instanceof Error) {
    process.stderr.write(`rabbitmq-init: ${error.name}\n`);
  }
  process.exitCode = 1;
});
