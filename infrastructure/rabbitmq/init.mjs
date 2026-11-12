#!/usr/bin/env node
// RabbitMQ provisioning for topology v10 (step 3.2 Q5, Q10, ADR-0024; v2: step 3.3 L7; v3: step
// 4.1 S2, ADR-0026; v4: step 4.2 A2, ADR-0028; v5: step 4.3 U2, ADR-0029; v6: step 4.4 B3,
// ADR-0033; v7: step 4.5 D2, ADR-0036; v8: step 4.6 X11, ADR-0040; v9: step 5.2 P15, ADR-0044;
// v10: step 5.3 Q27, ADR-0046).
// The only code that declares broker objects: services verify passively and their users cannot
// configure.
//
//   node init.mjs [--vhost <name>] [--mgmt-url <url>] [--definitions <path>]
//                 [--users] [--cleanup-legacy] [--legacy-vhost <name>]
//   node init.mjs --prune-dry-run [--vhost <name>] # list the bindings step 4 would remove; no change
//   node init.mjs --delete-vhost <name>            # test teardown; refuses email-gateway and /
//
// Plain Node 22 (ESM, global fetch, no dependencies) against the management HTTP API, as the
// administrator (RABBITMQ_USER / RABBITMQ_PASSWORD). Steps, all idempotent:
//   1. wait for the management API (up to 120 s);
//   2. create/update the vhost (description "email-gateway topology v<N>", default queue type
//      quorum) and grant the administrator full permissions on it;
//   3. import definitions.json (exchanges, quorum queues, bindings, policies) into the vhost;
//   4. prune bindings: an import only adds, so a binding that an earlier topology version
//      declared and this one does not (v3: the two event bindings of scan.auth; v5: the
//      unqualified retry binding retry.scan.url.# of scan.url; v8: scan.sandbox's
//      sandbox_requested.v1 binding and its unqualified retry.scan.sandbox.#; v9: email.archive's
//      mail.policy.decided.v1 binding on email.policy; v10: email.quarantine's
//      mail.policy.decided.v1 binding on email.policy) is removed. Only
//      bindings whose destination is a queue or exchange of the definitions are touched; objects
//      outside the topology are never changed. Logs binding names and counts only;
//   5. --users: create/update the role users (no tags) with exactly their Q10 permissions and
//      their topic permissions (routing keys each user may publish per exchange; every other
//      topic permission of the user on the vhost is removed);
//   6. --cleanup-legacy: delete the ADR-0005 objects on vhost "/" only when empty (queues with
//      no messages and no consumers; RabbitMQ 4.x refuses `if-empty` deletes of quorum queues,
//      so emptiness is checked first); --legacy-vhost points it at another vhost (tests only);
//   7. verify: exactly the 6 exchanges and 20 quorum queues, exactly the bindings of the
//      definitions (no missing and no extra binding), every policy applied, and (--users) each
//      role user's permissions and topic permissions exactly.
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
 * hops of its own queue, ops (dead-letter replay) the retry hops of the replayable work queues).
 * Topology v3 (step 4.1 S2) adds the scanner (email-worker scan role, queue scan.spam) and gives
 * ops the retry hops of scan.spam. Topology v4 (step 4.2 A2) extends the scanner to the
 * attachment engine's work queue scan.attachment (same user: same image and bounded context,
 * ADR-0028) and gives ops the retry hops of scan.attachment. The scanner never publishes
 * mail.attachment.sandbox_requested.v1 itself (outbox → relay). The relay needs nothing new: the
 * reconciler re-drives an event through its outbox row, so the relay republishes it with its own
 * `org.` event key.
 *
 * Topology v5 (step 4.3 U2) extends the scanner to the URL engine (scan.url) and the inspection
 * results (scan.url.results); its retry and dead-letter keys are anchored on `.org.` so that the
 * `url` alternative never covers the hops of scan.url.inspect (a dot-extension of scan.url). The
 * new url-browser user (the isolated browser worker, no database) reads only scan.url.inspect and
 * publishes only its own result event key (`mail.url.inspection_completed.v1`, direct publish with
 * confirms) and its queue's retry/dead-letter hops; it configures nothing. ops may replay the
 * three new work queues. The click-service has no broker user (its events go through the outbox).
 *
 * Topology v6 (step 4.4 B3) extends the scanner to the phishing/BEC engine's work queue scan.bec
 * (same user and image; the stage-2 trigger mail.message.scan_stage_ready.v1 is written to the
 * outbox and published by the relay, which already publishes `org.` keys to email.security) and
 * gives ops the retry hops of scan.bec. The scanner's retry/dead-letter keys keep the `.org.`
 * anchoring of v5 (`bec` is no dot-prefix of another queue, so it needs none, but one pattern
 * serves every scanner queue).
 *
 * Topology v7 (step 4.5 D2) extends the scanner to the data loss prevention engine's work queue
 * scan.dlp (same user and image; the incident event mail.message.dlp_incident.v1 is written to
 * the outbox and published by the relay, so the scanner never publishes it) and gives ops the
 * retry hops of scan.dlp. The `.org.` anchoring of v5 is kept.
 *
 * Topology v8 (step 4.6 X11) extends the scanner to the email-worker's two sandbox queues
 * (scan.sandbox.submissions: the dispatcher; scan.sandbox.results: the results consumer); the
 * `.org.`-anchored retry/dead-letter keys keep them apart from scan.sandbox (the controller's
 * queue, a dot-prefix of both) and from each other. The task (mail.sandbox.task_requested.v1) and
 * the completion (mail.attachment.sandbox_completed.v1) go through the outbox, so the scanner
 * publishes neither. The new sandbox-controller user (the isolated controller, no database) reads
 * only scan.sandbox and publishes only its own result key (`mail.sandbox.task_completed.v1`,
 * direct publish with confirms) and the hops of its own queue (its retry key is the qualified
 * `retry.scan.sandbox.org.`, its dead-letter keys `dead-letter.scan.sandbox[.org.…]`, so it can
 * never publish into the email-worker's sandbox queues); it configures nothing. ops may replay
 * the three sandbox work queues. The relay needs nothing new.
 *
 * Topology v9 (step 5.2 P15, ADR-0044) adds two users. policy-engine (the delivery gate) reads
 * only email.policy.evaluate and publishes only the retry hops of that queue on email.policy and
 * its dead-letter hops on email.events: its decisions, approvals, archive and notification
 * requests all go through the outbox and the relay (the relay already publishes `org.` keys to
 * every exchange, so it needs nothing new: EVENT_KEYS covers the three new event types).
 * notification-worker reads only email.notifications and publishes only that queue's retry
 * (email.policy) and dead-letter (email.events) hops. Neither configures anything. ops may replay
 * the two new work queues (home exchange email.policy). Neither new queue name is a dot-prefix of
 * another, so the plain `retry.<queue>.` prefix cannot reach another queue.
 *
 * Topology v10 (step 5.3 Q27, ADR-0046) makes email.quarantine the work queue of the
 * policy-engine's `quarantine` role (the release executor): policy-engine also reads
 * email.quarantine and publishes its retry (email.policy) and dead-letter (email.events) hops;
 * releases, approvals and notifications still go through the outbox (the relay's `org.` grant
 * covers the two new event types). ops may replay email.quarantine. `email.quarantine` is no
 * dot-prefix of another queue name, and `email.policy.evaluate` / `email.quarantine` never share a
 * prefix, so the alternation cannot reach another queue's hops.
 */
const SCANNER_QUEUES =
  '(spam|attachment|url|url\\.results|bec|dlp|sandbox\\.submissions|sandbox\\.results)';
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
    // Step 4.1 S1/S2: the email-worker scan role has its own broker user (least privilege).
    // Step 4.2 A2 (v4): the same user consumes scan.attachment (the attachment engine); step 4.3
    // (v5) scan.url and scan.url.results; step 4.4 B3 (v6) scan.bec (the BEC engine); step 4.5
    // D2 (v7) scan.dlp (the DLP engine); step 4.6 X11 (v8) scan.sandbox.submissions and
    // scan.sandbox.results (the sandbox engine's dispatcher and results consumer).
    role: 'scanner',
    userKey: 'RABBITMQ_SCANNER_USER',
    passwordKey: 'RABBITMQ_SCANNER_PASSWORD',
    configure: '^$',
    write: '^email\\.(security|events)$',
    read: `^scan\\.${SCANNER_QUEUES}$`,
    topics: [
      topic('email.security', `^retry\\.scan\\.${SCANNER_QUEUES}\\.org\\.`),
      topic('email.events', `^dead-letter\\.scan\\.${SCANNER_QUEUES}(\\.org\\.|$)`),
    ],
  },
  {
    // Step 4.3 U2, U15 (v5): the isolated url-browser-worker. Reads its one queue, publishes only
    // its result events (with publisher confirms) and the hops of its own queue.
    role: 'url-browser',
    userKey: 'RABBITMQ_URL_BROWSER_USER',
    passwordKey: 'RABBITMQ_URL_BROWSER_PASSWORD',
    configure: '^$',
    write: '^email\\.(security|events)$',
    read: '^scan\\.url\\.inspect$',
    topics: [
      topic(
        'email.security',
        '^(org\\.[1-9][0-9]{0,19}\\.mail\\.url\\.inspection_completed\\.v1$|retry\\.scan\\.url\\.inspect\\.)',
      ),
      topic('email.events', '^dead-letter\\.scan\\.url\\.inspect(\\.|$)'),
    ],
  },
  {
    // Step 4.6 X1, X11 (v8): the isolated sandbox-controller. Reads its one queue, publishes only
    // its result events (with publisher confirms) and the hops of its own queue (`.org.`
    // anchored: scan.sandbox is a dot-prefix of scan.sandbox.submissions / .results).
    role: 'sandbox-controller',
    userKey: 'RABBITMQ_SANDBOX_USER',
    passwordKey: 'RABBITMQ_SANDBOX_PASSWORD',
    configure: '^$',
    write: '^email\\.(security|events)$',
    read: '^scan\\.sandbox$',
    topics: [
      topic(
        'email.security',
        '^(org\\.[1-9][0-9]{0,19}\\.mail\\.sandbox\\.task_completed\\.v1$|retry\\.scan\\.sandbox\\.org\\.)',
      ),
      topic('email.events', '^dead-letter\\.scan\\.sandbox(\\.org\\.|$)'),
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
    // Step 5.2 P13, P15 (v9): the policy-engine, the delivery gate; step 5.3 Q27 (v10): also the
    // release executor (role `quarantine`) on email.quarantine. Reads its two queues; every event
    // it produces goes through the outbox (the relay publishes it).
    role: 'policy-engine',
    userKey: 'RABBITMQ_POLICY_ENGINE_USER',
    passwordKey: 'RABBITMQ_POLICY_ENGINE_PASSWORD',
    configure: '^$',
    write: '^email\\.(policy|events)$',
    read: '^email\\.(policy\\.evaluate|quarantine)$',
    topics: [
      topic('email.policy', '^retry\\.email\\.(policy\\.evaluate|quarantine)\\.'),
      topic('email.events', '^dead-letter\\.email\\.(policy\\.evaluate|quarantine)(\\.|$)'),
    ],
  },
  {
    // Step 5.2 P15, P25 (v9): the notification-worker (policy alerts and sender notices).
    role: 'notification-worker',
    userKey: 'RABBITMQ_NOTIFICATION_USER',
    passwordKey: 'RABBITMQ_NOTIFICATION_PASSWORD',
    configure: '^$',
    write: '^email\\.(policy|events)$',
    read: '^email\\.notifications$',
    topics: [
      topic('email.policy', '^retry\\.email\\.notifications\\.'),
      topic('email.events', '^dead-letter\\.email\\.notifications(\\.|$)'),
    ],
  },
  {
    role: 'ops',
    userKey: 'RABBITMQ_OPS_USER',
    passwordKey: 'RABBITMQ_OPS_PASSWORD',
    configure: '^$',
    // Replay republishes only to the home exchanges of the replayable work queues (Q9); v3 adds
    // scan.spam, v4 scan.attachment, v5 scan.url, scan.url.inspect and scan.url.results, v6
    // scan.bec, v7 scan.dlp, v8 scan.sandbox, scan.sandbox.submissions and scan.sandbox.results
    // (home exchange email.security), v9 email.policy.evaluate and email.notifications, v10
    // email.quarantine (home exchange email.policy).
    write: '^email\\.(ingestion|delivery|security|policy)$',
    read: '^email\\.dead-letter$',
    topics: [
      topic('email.ingestion', '^retry\\.email\\.received\\.'),
      topic('email.delivery', '^retry\\.email\\.delivery\\.pending\\.'),
      topic(
        'email.security',
        '^retry\\.scan\\.(spam|attachment|url|url\\.inspect|url\\.results|bec|dlp|sandbox|sandbox\\.submissions|sandbox\\.results)\\.',
      ),
      topic('email.policy', '^retry\\.email\\.(policy\\.evaluate|notifications|quarantine)\\.'),
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
    pruneDryRun: false,
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
      case '--prune-dry-run':
        options.pruneDryRun = true;
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

/**
 * Bindings on topology-owned destinations (queues and exchanges of the definitions) that the
 * definitions do not declare. The default exchange's implicit bindings (source '') are ignored.
 */
async function staleBindings(request, vhost, definitions) {
  const ownedQueues = new Set(definitions.queues.map((q) => q.name));
  const ownedExchanges = new Set(definitions.exchanges.map((e) => e.name));
  const expected = new Set(definitions.bindings.map(bindingId));
  const { data } = await request('GET', `/bindings/${enc(vhost)}`);
  return (Array.isArray(data) ? data : []).filter((b) => {
    if (b.source === '') return false;
    const owned =
      b.destination_type === 'queue'
        ? ownedQueues.has(b.destination)
        : b.destination_type === 'exchange' && ownedExchanges.has(b.destination);
    return owned && !expected.has(bindingId(b));
  });
}

async function pruneBindings(request, vhost, definitions, { dryRun = false } = {}) {
  const stale = await staleBindings(request, vhost, definitions);
  for (const b of stale) {
    if (dryRun) {
      log(`would remove binding ${bindingId(b)}`);
      continue;
    }
    const kind = b.destination_type === 'queue' ? 'q' : 'e';
    await request(
      'DELETE',
      `/bindings/${enc(vhost)}/e/${enc(b.source)}/${kind}/${enc(b.destination)}/${enc(b.properties_key)}`,
      undefined,
      { allow: [404] },
    );
    log(`removed binding ${bindingId(b)}`);
  }
  log(
    `${dryRun ? 'prune dry run: ' : ''}${stale.length} binding(s) on topology objects of ${vhost} ` +
      `${dryRun ? 'would be' : 'were'} removed (not in the definitions)`,
  );
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
  if (vhost === '/') throw new InitError('the topology is never provisioned on vhost "/"');
  const definitions = loadDefinitions(options.definitions);
  if (options.pruneDryRun) {
    await pruneBindings(request, vhost, definitions, { dryRun: true });
    return;
  }
  await ensureVhost(request, vhost, definitions.topology_version, adminUser);
  await importDefinitions(request, vhost, definitions);
  await pruneBindings(request, vhost, definitions);
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
