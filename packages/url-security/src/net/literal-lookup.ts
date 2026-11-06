import { isIP, type LookupFunction } from 'node:net';

/**
 * `lookup` for sockets that dial a validated IP literal: Node's connect path (happy eyeballs)
 * calls `lookup` even for literals; this one answers only with the literal itself and refuses
 * every name, so no DNS resolution can ever happen on the guarded connector.
 */
export const literalOnlyLookup: LookupFunction = (hostname, options, callback) => {
  const family = isIP(hostname);
  if (family === 0) throw new Error('DNS lookup is not allowed on the guarded connector');
  if (options.all) callback(null, [{ address: hostname, family }]);
  else callback(null, hostname, family);
};
