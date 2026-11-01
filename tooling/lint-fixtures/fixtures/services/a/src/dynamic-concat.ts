export async function load(): Promise<unknown> {
  return await import('../../b/src/' + 'x.js');
}
