import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { toRabbitDefinitions } from '../definitions';
import { DEFAULT_VHOST, TOPOLOGY, validateTopology } from '../topology';

/**
 * Writes the RabbitMQ definitions of the topology (`TOPOLOGY_VERSION`, step 3.2 Q5):
 *
 *   node dist/cli/export-definitions.js <output.json>
 *
 * `pnpm --filter @email-gateway/event-contracts topology:export` builds, runs this with
 * `infrastructure/rabbitmq/definitions.json` and formats the file with Prettier.
 */
function main(): void {
  const target = process.argv[2];
  if (!target) {
    process.stderr.write('usage: export-definitions <output.json>\n');
    process.exitCode = 2;
    return;
  }
  const violations = validateTopology(TOPOLOGY);
  if (violations.length > 0) {
    process.stderr.write(`topology is invalid:\n${violations.map((v) => `  - ${v}`).join('\n')}\n`);
    process.exitCode = 1;
    return;
  }
  const definitions = toRabbitDefinitions(TOPOLOGY, { vhost: DEFAULT_VHOST });
  const path = resolve(target);
  writeFileSync(path, `${JSON.stringify(definitions, null, 2)}\n`);
  process.stdout.write(
    `wrote ${path}: topology v${definitions.topology_version}, ${definitions.exchanges.length} exchanges, ` +
      `${definitions.queues.length} queues, ${definitions.bindings.length} bindings, ` +
      `${definitions.policies.length} policies\n`,
  );
}

main();
