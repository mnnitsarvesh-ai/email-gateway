// The `testing` surface (D6): the in-process provider fake, the reusable client contract suite
// and runtime test helpers. Exported from the package root as the `testing` namespace (the
// skeleton's package.json has no `exports` map for a subpath, D-WP2 §13).
export * from './fake-provider-server';
export * from './helpers';
export * from './contract';
