// @email-gateway/message-lifecycle (step 3.3 L1, ADR-0025): the fifteen lifecycle states, the
// transition table as data, the pure ordering rule, the derived delivery state and the
// transition service, the only writer of the message lifecycle columns and their history.
export * from './states';
export * from './transitions';
export * from './decide';
export * from './derive';
export * from './initial';
export * from './keys';
export * from './errors';
export * from './metrics';
export * from './events';
export * from './service';
