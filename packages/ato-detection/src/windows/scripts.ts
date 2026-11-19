/**
 * Lua scripts of the ATO windows (step 8.4 D8). Each update is applied atomically and at most once
 * per source event: the `ato:dd:*` marker is `SET NX EX` first, and the counters and sets change
 * only when the marker was new. The test kit's `InMemoryRedis` recognizes these exact texts and
 * runs equivalent JavaScript; the package integration test runs them against a real Redis.
 */

/**
 * KEYS[1] = dedupe marker; KEYS[2..n] = target keys.
 * ARGV[1] = marker TTL (s); then four ARGV per target: op, ttl, arg, cap.
 * Ops: `incr` (INCRBY arg, EXPIRE ttl), `incr_nx` (INCRBY arg, EXPIRE only when the key has no TTL),
 * `sadd` (SADD arg unless the set holds `cap` members, EXPIRE ttl), `sadd_nx` (same, TTL only once).
 * Returns 1 when applied, 0 for a duplicate.
 */
export const RECORD_SCRIPT = `
if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[1])) then return 0 end
for i = 2, #KEYS do
  local base = 2 + (i - 2) * 4
  local op = ARGV[base]
  local ttl = tonumber(ARGV[base + 1])
  local arg = ARGV[base + 2]
  local cap = tonumber(ARGV[base + 3])
  local key = KEYS[i]
  if op == 'incr' or op == 'incr_nx' then
    redis.call('INCRBY', key, tonumber(arg))
    if op == 'incr' or redis.call('TTL', key) < 0 then redis.call('EXPIRE', key, ttl) end
  elseif op == 'sadd' or op == 'sadd_nx' then
    if redis.call('SISMEMBER', key, arg) == 0 and redis.call('SCARD', key) < cap then
      redis.call('SADD', key, arg)
    end
    if op == 'sadd' or redis.call('TTL', key) < 0 then redis.call('EXPIRE', key, ttl) end
  end
end
return 1
`;

/** Number of distinct members across the sets in KEYS (SUNION). */
export const UNION_COUNT_SCRIPT = `
return #redis.call('SUNION', unpack(KEYS))
`;

/** Members of the set KEYS[1]. */
export const MEMBERS_SCRIPT = `
return redis.call('SMEMBERS', KEYS[1])
`;

/**
 * KEYS[1] = set; ARGV[1] = member, ARGV[2] = cap, ARGV[3] = ttl. Adds the member unless the set is
 * full; refreshes nothing else. Returns 1 when newly added, 0 when present or full.
 */
export const SEEN_ADD_SCRIPT = `
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then return 0 end
if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end
redis.call('SADD', KEYS[1], ARGV[1])
if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3])) end
return 1
`;

/**
 * Platform IP campaign window (D8). KEYS[1] = dedupe marker, KEYS[2] = failure counter of the
 * minute, KEYS[3] = account set of the 10-minute bucket, KEYS[4] = flag, KEYS[5..] = the account
 * sets of the window (including KEYS[3]).
 * ARGV: marker TTL, window TTL, account HMAC, set cap, minimum accounts, flag TTL.
 * Returns {applied, distinctAccounts, flagged, newlyFlagged}.
 */
export const IP_FAILURE_SCRIPT = `
local applied = 0
if redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[1])) then
  applied = 1
  redis.call('INCR', KEYS[2])
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[2]))
  if redis.call('SISMEMBER', KEYS[3], ARGV[3]) == 0 and redis.call('SCARD', KEYS[3]) < tonumber(ARGV[4]) then
    redis.call('SADD', KEYS[3], ARGV[3])
  end
  redis.call('EXPIRE', KEYS[3], tonumber(ARGV[2]))
end
local sets = {}
for i = 5, #KEYS do sets[#sets + 1] = KEYS[i] end
local distinct = #redis.call('SUNION', unpack(sets))
local flagged = 0
local newly = 0
if distinct >= tonumber(ARGV[5]) then
  if redis.call('EXISTS', KEYS[4]) == 0 then
    newly = 1
    redis.call('SET', KEYS[4], 'campaign|' .. distinct, 'EX', tonumber(ARGV[6]))
  else
    redis.call('SET', KEYS[4], 'campaign|' .. distinct, 'KEEPTTL')
  end
  flagged = 1
elseif redis.call('EXISTS', KEYS[4]) == 1 then
  flagged = 1
end
return {applied, distinct, flagged, newly}
`;
