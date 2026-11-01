export async function load(): Promise<unknown> {
  const { createRequire } = await import('node:module');
  return createRequire(import.meta.url);
}
