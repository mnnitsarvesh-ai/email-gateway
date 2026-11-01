export async function load(): Promise<unknown> {
  return await import('file:///repo/services/b/src/x.js');
}
